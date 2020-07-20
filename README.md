# Sheep Bridge

The SheepShaver and Basilisk II classic Mac emulators implement a simple, UDP-based
network protocol that allows two virtual machines to communicate. Sheep Bridge allows
a physical, Linux-based machine to communicate with the virtual machines using a TAP
interface.

This allows the Linux machine to provide Internet access to the virtual machines, or
other services like AppleTalk.

## Requirements

A Linux machine with Python 3.

## General usage

Let’s suppose you have two machines on the `192.168.1.0/24` network:
 - `192.168.1.2` will run Sheep Bridge
 - `192.168.1.3` will run SheepShaver or Basilisk II.

On `192.168.1.3`, edit the emulator configuration file (`~/.basilisk_ii_prefs` for
Basilisk II) and set the following options:
```
udptunnel true
udpport 6066
```

(you can specify another port than `6066` -- in that case you will need to adjust
Sheep Bridge’s configuration)

Make sure that the configuration file does *not* contain any `ether ...` option.

On `192.168.1.2`, start Sheep Bridge:
```
# ./sheep_bridge.py 192.168.1.2/24 6066
```

Sheep Bridge needs to be started as root in order to create the TAP interface. It will
drop its privileges once it’s done. You should now have a `sheep_bridge` Ethernet
interface.

You can assign an IP and netmask to the `sheep_bridge` interface. (Do not use a
network range already used on your network). For instance:
```
# ip addr add 10.42.42.1/24 dev sheep_bridge
# ip link set sheep_bridge up
```

Configure Mac OS in your Sheep Shaver/Basilisk II to use an address on the same network
(for instance `10.42.42.2`) and you should be able to communicate between the machines.

### `systemd` integration

Sheep Bridge can be used with `systemd`:

 - Copy `sheep-bridge.defaults` to `/etc/default/sheep-bridge` and edit the `NET_ADDR`
   and `PORT` parameters.
 - Copy `sheep-bridge.service` to `/etc/systemd/system/sheep-bridge.service`.
 - Copy `sheep_bridge.py` to `/usr/local/sbin/sheep_bridge.py`.
 - Run `systemctl enable sheep-bridge` and `systemctl start sheep-bridge` as root.

Sheep Bridge will be started before network configuration tools, so you can use them
to configure the `sheep_bridge` interface the same way physical network interfaces
are configured.

For instance, on Debian, you can use the following configuration in
`/etc/network/interfaces`:

```
allow-hotplug sheep_bridge
iface sheep_bridge inet static
	address 10.42.42.1
	netmask 255.255.255.0
```

You can also install a DHCP server on the Sheep Bridge machine and use it to assign
addresses to the virtual machines.

### Internet access

You can configure Internet sharing to allow the virtual machines to access the Internet.
See your distribution’s documentation for details. It usually boils down to:

 - Enable IP forwarding (`net.ipv4.ip_forward=1` in `/etc/sysctl.conf` or equivalent)
 - Enable masquerading (`iptables -t nat -A POSTROUTING -j MASQUERADE`)

### AppleTalk

The `netatalk` v2 (not v3) tools can be used to share files between the virtual machines
and the Linux host.

 - This requires support for the AppleTalk protocol in the Linux kernel. It is generally
   available, but there are some caveats (see [this gist](
   https://gist.github.com/VinDuv/4db433b6dce39d51a5b7847ee749b2a4) for details)
 - Make sure that the `sheep_bridge` interface is enabled (up) on boot (no need to
   assign it an IP address, though)
 - The `atalkd` daemon must be enabled, and must be configured to use the `sheep_bridge`
   interface.
 - The `afpd` daemon must be configured to allow file sharing over AppleTalk (use
   `-ddp` or `-transall` in `afpd.conf`)
 - AppleTalk routing can be used to allow communication between SheepShaver/Basilisk II
   and physical Mac computers. Configure `atalkd` to configure routing between the
   `sheep_bridge` interface, and the interface whose Macs are connected to.
   Unfortunately, there is an issue with Linux’s AppleTalk implementation that will
   prevent router discovery from working properly unless you recompile the kernel; see
   the aforementioned gist for more info.

### Network issues

Sheep Bridge perform checks on packets received from the VMs, and packets received on the
virtual Ethernet interface, before transmitting them.

 - Packets sent to multicast destinations are disallowed, with the exception of the
   standard broadcast address (`FF:FF:FF:FF:FF:FF`) and the AppleTalk broadcast address
   (`09:00:07:FF:FF:FF`). IPv6 auto-configuration packets are silently dropped if they
   are sent on the virtual Ethernet interface.
 - SheepShaver/Basilisk II VMs (and Sheep Bridge) use local MAC addresses that are
   derived from the host computer’s IP address. Sheep Bridge checks the coherency between
   MAC addresses and IP addresses before forwarding a packet. Unfortunately,
   SheepShaver/Basilisk II may use incoherent addresses if the computer it’s running on
   has multiple interfaces active at the same time (for instance, Ethernet and Wi-Fi).
   In that case, you will have to disable one of the interfaces and try again.

When an unexpected/invalid packet is received, Sheep Bridge will log a message on the
standard output, so you can directly debug issues if you started it manually. If it is
started using `systemd`, the output will usually be redirected to `journal` or the 
`/var/log/syslog` file.
