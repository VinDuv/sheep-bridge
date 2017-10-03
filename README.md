# Sheep Bridge

The SheepShaver and Basilisk II classic Mac emulators provide a simple way to create a
network between two virtual machines: UDP encapsulation.

Sheep Bridge allows a physical machine to join the network. It can then provide Internet
access to the virtual machines, or other services like AppleTalk.

## Requirements

A Linux machine with Python 3. Sheep Bridge should be easily portable to other Unix
systems with TAP network interfaces; patches welcome ;-) It may also be possible to
make it run under Python 2 with some small modifications.

## How to use it

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

### IP configuration

You can assign an IP and netmask to the `sheep_bridge` interface. Do *not* use a network
that would conflict with you physical network, or chaos may ensue.

For instance, you can configure IP `10.42.42.1/24` on the interface with:
```
# ifconfig sheep_bridge 10.42.42.1 netmask 255.255.255.0 up
```

Alternatively, you can configure your distro’s network config tool so it sets up the
interface when Sheep Bridge is started. For instance, on Debian, you can add the
following lines to `/etc/network/interfaces`:

```
allow-hotplug sheep_bridge
iface sheep_bridge inet static
	address 10.42.42.1
	netmask 255.255.255.0
	pre-up sysctl -w net.ipv6.conf.$IFACE.disable_ipv6=1
```

(the `pre-up` line is not strictly necessary, but will avoid unnecessary IPv6 traffic
on the virtual network; after all, most OSes that can run in SheepShaver and Basilisk II
are not IPv6-compatible…)

Now, you can start the virtual machine and set its IP in the MacTCP or TCP/IP control
panel (for instance, `10.42.42.2`, netmask `255.255.255.0`). You should be able to ping
the Sheep Brige machine:

![TCP/IP control panel and MacTCP Ping](https://www.duvert.net/images/sheep_bridge_01.png)

You can also install a DHCP server on the Sheep Bridge machine and use it to assign
addresses to the virtual machines. (The VMs will need System 7 or newer and Open
Transport, I believe)

### Internet access

Now that the IP addresses are configured, you can share the network connection on, say,
the `eth0` interface of the Sheep Bridge machine and the virtual machines with:
```
# echo 1 > /proc/sys/net/ipv4/ip_forward
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

The virtual machines should now be able to access the Internet.

### AppleTalk

If `netatalk` is installed on the Sheep Bridge machine, you can use it to share files
via AppleTalk with the virtual machines. IP configuration (see above) is not necessary,
but you will still need to bring the `sheep_bridge` interface up before starting the
`netatalk` daemons. Netatalk also needs to be configured to use AFP over AppleTalk,
which is disabled by default (hint: use `-ddp` or `-transall` in `afpd.conf` and make sure
the `atalkd` daemon is enabled).

You need to configure `atalkd.conf` so that it uses the `sheep_bridge` interface. Once
it’s done, the virtual machines should be able to access the AppleShare file server.

If you have old Macs on your physical network, you should be able to make netatalk serve
files to both them and the virtual machines, and even route AppleTalk packet between
the two networks (so your VM can access a file share on a physical Mac and vice-versa). I
haven’t been able to find a working configuration for this, however.

## TODO
 * `systemd` service support, to be able to start sheep_bridge at system startup
 * Ability to use a persistent TAP interface to avoid having to start the service as root

