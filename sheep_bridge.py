#!/usr/bin/python3 -u

"""
Sheep Bridge creates an Ethernet interface to communicate with Basilisk II and
SheepShaver virtual machines using the UDP tunnel network option.
"""

import argparse
import asyncio
import errno
import fcntl
import ipaddress
import os
import re
import socket
import struct
import sys

# pylint: disable=bad-continuation


MAC_PREFIX = b'\x42\x32' # First 2 bytes of a VM MAC address

# Allowed broadcast/multicast MACs
ALLOWED_MCAST_MACS = (
    b'\xff\xff\xff\xff\xff\xff',  # Broadcast address
    b'\x09\x00\x07\xff\xff\xff',  # AppleTalk broadcast address
)

# Filtered broadcast/multicast MACs prefixes. Packets received on the TAP with
# these addresses as destination are silently dropped.
FILTERED_MCAST_PREFIXES = (
    b'\x33\x33',  # IPv6 multicast
)


class TapDevice():
    """
    A TAP device to send and receive raw Ethernet frames.
    The delegate attribute must be set before the async loop runs.
    """

    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454ca
    SIOCSIFHWADDR = 0x8924
    ARPHRD_ETHER = 1

    def __init__(self, name, ip_addr):
        self.delegate = None
        self.own_mac = MAC_PREFIX + ip_addr.packed

        self._fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        self._buf = bytearray(1500)
        self._writable = True

        ifreq = struct.pack('@16sh', name, self.IFF_TAP | self.IFF_NO_PI)
        try:
            fcntl.ioctl(self._fd, self.TUNSETIFF, ifreq)
        except PermissionError:
            sys.exit("Permission error while creating the TAP interface. "
                "Ensure that this program is started as the root user.")

        ifreq = struct.pack('@16sh6s', b'', self.ARPHRD_ETHER,
            self.own_mac)
        fcntl.ioctl(self._fd, self.SIOCSIFHWADDR, ifreq)

        asyncio.get_event_loop().add_reader(self._fd, self._data_available)

    def write_from(self, buf, length):
        """
        Write length bytes from the start of the specified buffer object to the
        interface
        """

        if not self._writable:
            return

        try:
            os.write(self._fd, buf[0:length])
        except OSError as err:
            if err.errno != errno.EIO:
                raise

            sys.stderr.write("Unable to write to the TAP device. Check that "
                "the interface is up.\n")
            self._writable = False

            # Start monitoring the TAP device to become writable again
            asyncio.get_event_loop().add_writer(self._fd, self._fd_writable)

    def fileno(self):
        """
        Get the file descriptor for the TAP device (used by the asyncio waiter)
        """

        return self._fd

    def close(self):
        """
        Close the TAP device
        """

        evt_loop = asyncio.get_event_loop()

        if not self._writable:
            evt_loop.remove_writer(self._fd)

        evt_loop.remove_reader(self._fd)
        os.close(self._fd)
        self._fd = None

    def _data_available(self):
        """
        Called when data is available on the TAP device.
        """

        length = os.readv(self._fd, [self._buf])

        self.delegate.handle_tap_data(self._buf, length)

    def _fd_writable(self):
        """
        Called when the TAP device becomes writable after being not writable.
        """

        asyncio.get_event_loop().remove_writer(self._fd)
        self._writable = True

    @staticmethod
    def valid_tap_name(value):
        """
        Validate the name of a TAP device and return it as a byte array.
        """

        if not re.match(r'^[a-z0-9._-]+$', value):
            raise argparse.ArgumentTypeError("invalid interface name")

        return value.encode('ascii')


class NetworkSockets():
    """
    Manages the sockets used to communicate with the SheepShaver/Basilisk II
    VMs.
    If necessary, this function waits for the network to be available before
    binding the sockets.
    The delegate attribute must be set before the async loop runs.
    """

    RTMGRP_IPV4_IFADDR = 0x10  # Used for network notification changes

    def __init__(self, net_addr, port):
        self.delegate = None

        self._net_addr = net_addr
        self._port = port

        self._net_events_sock = None
        self._ucast_sock = None
        self._bcast_sock = None
        self._buf = bytearray(1500)

        print(f"Local address: {net_addr.ip}:{port}")

        net_events_sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
            socket.NETLINK_ROUTE)
        net_events_sock.bind((0, self.RTMGRP_IPV4_IFADDR))

        self._net_events_sock = net_events_sock

        evt_loop = asyncio.get_event_loop()

        evt_loop.add_reader(net_events_sock, self._net_event)
        evt_loop.call_soon(self._try_network_configuration)

    def send_broadcast(self, buffer, length):
        """
        Send a broadcast packet.
        """

        if self._bcast_sock is None:
            # Network configuration is not done so no packets can be sent
            return

        self._bcast_sock.sendto(buffer[:length], ('<broadcast>', self._port))

    def send_unicast(self, address, buffer, length):
        """
        Send a unicast packet.
        """

        if self._bcast_sock is None:
            # Network configuration is not done so no packets can be sent
            return

        self._ucast_sock.sendto(buffer[:length], (str(address), self._port))

    def close(self):
        """
        Close all network sockets.
        """

        evt_loop = asyncio.get_event_loop()

        if self._net_events_sock is not None:
            evt_loop.remove_reader(self._net_events_sock)
            self._net_events_sock.close()

        if self._ucast_sock is not None:
            evt_loop.remove_reader(self._ucast_sock)
            self._ucast_sock.close()

        if self._bcast_sock is not None:
            evt_loop.remove_reader(self._bcast_sock)
            self._bcast_sock.close()

        self._net_events_sock = None
        self._ucast_sock = None
        self._bcast_sock = None

    @property
    def own_ip(self):
        """
        Returns the IP address used by this machine to communicate with the VMs
        """

        return self._net_addr.ip

    @property
    def network(self):
        """
        Returns the IP network used by the VMs.
        """

        return self._net_addr.network

    def _net_event(self):
        """
        Called when data is received on the network event socket.
        """

        # Ignore the data received with the network change event; just
        # attempt to re-bind the socket
        self._net_events_sock.recv(4096)

        self._try_network_configuration()

    def _try_network_configuration(self):
        """
        Attempts to bind the network sockets.
        """

        first_try = False
        svc_status = ServiceStatus()

        if self._ucast_sock is None:
            first_try = True
            self._ucast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        ucast_sock = self._ucast_sock

        try:
            ucast_sock.bind((str(self._net_addr.ip), self._port))
        except OSError as err:
            if err.errno != errno.EADDRNOTAVAIL:
                raise

            if first_try:
                svc_status.status("Waiting for host IP configuration")
                print("Waiting for host IP to be configured on interface")
            return

        # Bind successful, finish network configuration
        evt_loop = asyncio.get_event_loop()

        evt_loop.remove_reader(self._net_events_sock)
        self._net_events_sock.close()
        self._net_events_sock = None

        # Basilisk II sends broadcast packets on the global broadcast
        # address, so we need to listen on this address
        self._bcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bcast_sock = self._bcast_sock
        bcast_sock.bind(('<broadcast>', self._port))

        bcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

        evt_loop.add_reader(self._bcast_sock, self._data_available,
            self._bcast_sock)

        evt_loop.add_reader(self._ucast_sock, self._data_available,
            self._ucast_sock)

        svc_status.status("Ready")
        print("Ready")

    def _data_available(self, sock):
        """
        Called when data is available on a socket.
        """

        length, address = sock.recvfrom_into(self._buf)

        if length == 0:
            raise EOFError(f"EOF reading from {sock}")

        self.delegate.handle_sock_data(address, self._buf, length)

    @staticmethod
    def valid_net_addr(value):
        """
        Validate the network address/netmask provided and return the
        value as a IPv4Interface object.
        """

        if '/' not in value:
            raise argparse.ArgumentTypeError("missing network mask "
                "(ex: 192.168.1.1/24)")

        try:
            network_addr = ipaddress.IPv4Interface(value)
        except ValueError as err:
            raise argparse.ArgumentTypeError(err)

        if not network_addr.ip.is_private:
            raise argparse.ArgumentTypeError("not a private IPv4 address")

        prefix = network_addr.network.prefixlen
        # Disallow /31 networks since they have no proper broadcast address
        if prefix in {0, 31, 32}:
            raise argparse.ArgumentTypeError(f"invalid network prefix "
                f"{prefix}")

        return network_addr

    @staticmethod
    def valid_port(value):
        """
        Validate the provided port and return the value as an int.
        """

        try:
            port = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("not an integer")

        if 1023 < port < 65536:
            return port

        # Do not allow privileged ports since it would require keeping
        # root privileges until the bind is successful.
        raise argparse.ArgumentTypeError("invalid port number (privileged "
            "ports are not supported)")


class NetworkBridge():
    """
    Bridges the TAP device and the network sockets.
    """

    def __init__(self, tap_device, net_sockets, port):
        self._tap_device = tap_device
        self._net_sockets = net_sockets
        self._port = port
        self._allowed_macs = frozenset(ALLOWED_MCAST_MACS +
            (tap_device.own_mac,))
        self._own_net = net_sockets.network
        self._own_ip = net_sockets.own_ip

        tap_device.delegate = self
        net_sockets.delegate = self

    def handle_tap_data(self, buffer, length):
        """
        Called when data is received on the TAP device. Check the data validity
        and redirects it to the appropriate socket.
        """

        if length < 14 or length > 1500:
            sys.stderr.write(f"Invalid data packet length {length} received "
                f"on TAP\n")
            return

        # Assume the source MAC is correctly set

        dest_mac = bytes(buffer[0:6])

        if dest_mac[0:2] == MAC_PREFIX:
            # Unicast packet
            address = ipaddress.IPv4Address(dest_mac[2:])
            own_net = self._own_net

            if (address not in own_net or address == own_net.network_address or
                address == own_net.broadcast_address):
                dest_mac = self._format_mac(dest_mac)

                sys.stderr.write(f"Incorrect destination MAC {dest_mac} "
                    f"received on TAP: {address} is not a valid local "
                    f"address\n")
                return

            self._net_sockets.send_unicast(address, buffer, length)
            return

        if dest_mac.startswith(FILTERED_MCAST_PREFIXES):
            # Ignore the packet
            return

        if dest_mac not in ALLOWED_MCAST_MACS:
            dest_mac = self._format_mac(dest_mac)
            sys.stderr.write(f"Incorrect destination MAC {dest_mac} received "
                f"on TAP; either unrecognized unicast or disallowed multicast")
            return

        self._net_sockets.send_broadcast(buffer, length)


    def handle_sock_data(self, address, buffer, length):
        """
        Called when data is received on the socket. Check the data validity
        and redirects it to the TAP device.
        """

        source_ip, port = address
        source_ip = ipaddress.IPv4Address(source_ip)

        if length < 14 or length > 1500:
            sys.stderr.write(f"Invalid data packet length {length} received "
                f"from {source_ip}:{port}\n")
            return

        if port != self._port:
            sys.stderr.write(f"Incorrect source port {port} received from "
                f"{source_ip}:{port}\n")
            return

        if source_ip == self._own_ip:
            # When sending a broadcast packet, it is sent back to us; ignore
            # it.
            return

        source_mac = buffer[6:12]
        expected_mac = MAC_PREFIX + source_ip.packed

        if source_mac != expected_mac:
            source_mac = self._format_mac(source_mac)
            expected_mac = self._format_mac(expected_mac)

            sys.stderr.write(f"Incorrect source MAC received from "
                f"{source_ip}:{port}: expected {expected_mac}, got "
                f"{source_mac}\n")
            return

        dest_mac = bytes(buffer[0:6])

        if dest_mac not in self._allowed_macs:
            dest_mac = self._format_mac(dest_mac)
            allowed_macs = ", ".join(self._format_mac(mac) for mac in
                self._allowed_macs)

            sys.stderr.write(f"Incorrect destination MAC {dest_mac} received "
                f"from {source_ip}:{port}: expected one of {allowed_macs}\n")

            return

        self._tap_device.write_from(buffer, length)

    @staticmethod
    def _format_mac(value):
        """
        Format a MAC address from its binary form.
        """

        return ":".join("%02X" % i for i in value)


class ServiceStatus():
    """
    Report the service status to the service manager, if any.
    """

    _instance = None

    def __init__(self):
        self._svc_sock = None

        sock_name = os.environ.get('NOTIFY_SOCKET')
        if sock_name is None:
            return

        svc_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        svc_sock.connect(sock_name)

        self._svc_sock = svc_sock

    def __new__(cls):
        if cls._instance is None:
            cls._instance = object.__new__(cls)

        return cls._instance

    def ready(self):
        """
        Indicates to the service manager that the service is ready.
        """

        if self._svc_sock is not None:
            self._svc_sock.sendall(b'READY=1')

    def shutting_down(self):
        """
        Indicates to the service manager that the service is shutting down.
        """

        if self._svc_sock is not None:
            self._svc_sock.sendall(b'STOPPING=1')

    def status(self, status_string):
        """
        Sends a status string to the service manager.
        """

        if self._svc_sock is not None:
            self._svc_sock.sendall(f"STATUS={status_string}".encode('utf-8'))


def run():
    """
    Main
    """

    parser = argparse.ArgumentParser(description="Ethernet bridge for "
                "Basilisk II / SheepShaver")
    parser.add_argument('net_addr', type=NetworkSockets.valid_net_addr,
        help="IP/mask of the host network")
    parser.add_argument('port', type=NetworkSockets.valid_port,
        help="UDP port to use")
    parser.add_argument('--iface', type=TapDevice.valid_tap_name,
        help="Created interface name", default='sheep_bridge')
    args = parser.parse_args()

    svc_status = ServiceStatus()

    tap_device = TapDevice(args.iface, args.net_addr.ip)
    net_sockets = NetworkSockets(args.net_addr, args.port)
    NetworkBridge(tap_device, net_sockets, args.port)

    # Signal that the service is ready as soon as the TAP interface is created,
    # even if the network address is not up yet.
    svc_status.ready()

    try:
        asyncio.get_event_loop().run_forever()
    finally:
        net_sockets.close()
        tap_device.close()

if __name__ == '__main__':
    run()
