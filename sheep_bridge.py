#!/usr/bin/env python3

"""
Sheep Bridge creates an Ethernet interface to communicate with Basilisk II and
SheepShaver virtual machines using the UDP tunnel network option.
"""

# Copyright 2017, Vincent Duvert <vincent@duvert.net>
# Distributed under the terms of the MIT License.

# pylint: disable=locally-disabled,bad-continuation,too-many-instance-attributes


import argparse
import asyncio
import fcntl
import ipaddress
import os
import pwd
import socket
import struct
import signal
import sys
import warnings


IFF_TUN = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca
SIOCSIFHWADDR = 0x8924
ARPHRD_ETHER = 1

ACTIVITY_TIMEOUT = 300
MAC_PREFIX = b"\x42\x32" # First 2 bytes of a VM MAC address, the others match the host IP


class TapDevice(object):
    """
    A TAP device to send and receive raw Ethernet frames.
    """

    def __init__(self, name, own_address):
        self._fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)

        ifreq = struct.pack("@16sh", name.encode('ascii'), IFF_TUN | IFF_NO_PI)
        try:
            fcntl.ioctl(self._fd, TUNSETIFF, ifreq)
        except PermissionError:
            sys.exit("Permission error while creating the TAP interface. Ensure that "
                     "this program is started as the root user.")

        ifreq = struct.pack("@16sh2s4s", b"", ARPHRD_ETHER, MAC_PREFIX,
            own_address.packed)
        fcntl.ioctl(self._fd, SIOCSIFHWADDR, ifreq)

    def read_into(self, buf):
        """
        Read a received Ethernet frame into the specified buffer object.
        Returns the read size
        """

        return os.readv(self._fd, [buf])

    def write_from(self, buf, length):
        """
        Write length bytes from the start of the specified buffer object to the interface
        """

        os.write(self._fd, buf[0:length])

    def fileno(self):
        """
        Get the file descriptor for the TAP device (used by the asyncio waiter)
        """

        return self._fd

    def close(self):
        """
        Close the TAP device
        """

        os.close(self._fd)


class SheepBridge(object):
    """
    Main class
    """

    def __init__(self):
        self._loop = None
        self._network_addr = None
        self._port = None
        self._tap = None
        self._ucast_sock = None
        self._bcast_sock = None
        self._buf = bytearray(1500)
        self._active_clients = {}
        self._broadcast_ip = None
        self._error = False

    def run(self):
        """
        Parse the command line arguments and start the bridge.
        """

        parser = argparse.ArgumentParser(description="Ethernet bridge for "
            "Basilisk II / SheepShaver")
        parser.add_argument('net_addr', help="IP/mask of the host network")
        parser.add_argument('port', type=int, help="UDP port to use")
        parser.add_argument('iface', help="Created interface name",
            nargs='?', default='sheep_bridge')
        args = parser.parse_args()

        self.run_args(args.net_addr, args.port, args.iface)

    def run_args(self, net_addr, port, name):
        """
        Start the bridge with the specified parameters
        """

        signal.signal(signal.SIGTERM, self._sigterm_handler)

        self._loop = asyncio.get_event_loop()
        self._configure_net(net_addr, port)
        self._tap = TapDevice(name, self._network_addr.ip)

        self._drop_privileges()

        self._loop.add_reader(self._tap, self._read_tap)
        self._loop.add_reader(self._ucast_sock, self._read_sock, self._ucast_sock,
            MAC_PREFIX + self._network_addr.ip.packed)
        self._loop.add_reader(self._bcast_sock, self._read_sock, self._bcast_sock, None)

        self._run_event_loop()

        self._ucast_sock.close()
        self._bcast_sock.close()
        self._tap.close()

        if self._error:
            sys.exit(1)

    def _read_tap(self):
        """
        Handle data from the TAP device
        """

        length = self._tap.read_into(self._buf)

        dest_mac = self._buf[0:6]
        if dest_mac[0] & 0x1 == 0:
            # Unicast
            if dest_mac[0:2] == MAC_PREFIX:
                target_ip = ipaddress.IPv4Address(bytes(dest_mac[2:6]))
            else:
                target_ip = None
        else:
            # Multicast
            target_ip = self._broadcast_ip

        if target_ip is not None:
            dest = (str(target_ip), self._port)
            sent_length = self._ucast_sock.sendto(self._buf[0:length], dest)

            assert sent_length == length

    def _read_sock(self, sock, expected_dest_mac):
        """
        Handle data from the socket. expected_dest_mac is the expected destination MAC
        address in the message, None if a broadcast message is expected
        """

        length, (host_ip, _port) = sock.recvfrom_into(self._buf)
        host_ip = ipaddress.IPv4Address(host_ip)

        dest_mac = self._buf[0:6]
        if dest_mac[0] & 0x1 != 0:
            # Broadcast address
            dest_mac = None

        source_mac = self._buf[6:12]
        expected_source_mac = MAC_PREFIX + host_ip.packed

        if dest_mac != expected_dest_mac or source_mac != expected_source_mac:
            return

        self._refresh_client(host_ip)

        self._tap.write_from(self._buf, length)

    def _refresh_client(self, host_ip):
        """
        Notify activity from the specified client IP
        """

        timer = self._active_clients.get(host_ip)
        if timer is None:
            print("Client %s is now active." % host_ip)
        else:
            timer.cancel()

        self._active_clients[host_ip] = self._loop.call_later(ACTIVITY_TIMEOUT,
            self._inactive_client, host_ip)

        if timer is None:
            # New client, so the broadcast IP may need update
            self._update_broadcast_ip()

    def _inactive_client(self, host_ip):
        """
        Mark a specified client IP as inactive
        """

        del self._active_clients[host_ip]
        print("Client %s is now inactive." % host_ip)

        self._update_broadcast_ip()

    def _update_broadcast_ip(self):
        """
        Determines on which IP to send broadcast Ethernet frames and updates
        the _broadcast_ip variable.
        """

        length = len(self._active_clients)

        if length == 0:
            # Send the broadcast messages to no one
            self._broadcast_ip = None

        elif length == 1:
            # Send the broadcast messages to the one client
            (self._broadcast_ip,) = self._active_clients.keys()

        else:
            # Send the broadcast messages to the UDP broadcast IP
            self._broadcast_ip = self._network_addr.network.broadcast_address

    def _configure_net(self, net_addr, port):
        """
        Configure the send/receive sockets given the provided IP network and mask
        """

        if "/" not in net_addr:
            sys.exit("Network address “%s” require a netmask (ex: 192.168.1.2/24)"
                % net_addr)

        try:
            network_addr = ipaddress.IPv4Interface(net_addr)
        except ValueError:
            sys.exit("“%s” is not a valid network address" % net_addr)

        self._network_addr = network_addr
        self._port = port

        if network_addr.network.prefixlen in {0, 32}:
            sys.exit("Invalid prefix length for network “%s”" % net_addr)

        self._ucast_sock = self._create_socket(network_addr.ip, self._port)
        self._bcast_sock = self._create_socket('<broadcast>', self._port)

    @staticmethod
    def _create_socket(address, port):
        """
        Create a listening/sending socket
        """

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.bind((str(address), port))
        except OSError as err:
            sys.exit("Unable to bind listening socket to address %s port %d: %s" %
                (address, port, err))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        return sock

    def _run_event_loop(self):
        """
        Run the asyncio event loop
        """

        self._loop.set_exception_handler(self._loop_exception_handler)

        try:
            self._loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()

    def _loop_exception_handler(self, loop, context):
        """
        Exception handler for the asyncore loop
        """

        self._error = True

        loop.default_exception_handler(context)
        loop.stop()

    @staticmethod
    def _parse_network(network_addr_string):
        """
        Parse the network address string and check if it’s valid
        """

        try:
            network_addr = ipaddress.IPv4Interface(network_addr_string)
        except ValueError:
            sys.exit("Invalid network “%s”" % network_addr_string)

        prefixlen = network_addr.network.prefixlen

        if prefixlen in {0, 32}:
            if "/" not in network_addr_string:
                sys.exit("Netmask required in network address “%s”" % network_addr_string)
            sys.exit("Invalid netmask for network “%s”" % network_addr_string)

        return network_addr

    @staticmethod
    def _drop_privileges():
        """
        Set the uid/gid to the nobody user
        """

        pw_info = pwd.getpwnam("nobody")
        os.setgid(pw_info.pw_gid)
        os.setuid(pw_info.pw_uid)

    @staticmethod
    def _sigterm_handler(_signum, _frame):
        """
        Handle SIGTERM by converting it to a KeyboardInterrupt
        """

        raise KeyboardInterrupt()


if __name__ == '__main__':
    SheepBridge().run()
    warnings.simplefilter('error')
