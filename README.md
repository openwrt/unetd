# unetd

unetd is a WireGuard based VPN daemon that simplifies creating and managing fully-meshed VPN connections between OpenWrt routers.

## Features

 - Splits network setup into network config (shared across all participating nodes) and local config (limited mostly to local private key, public signing device key, optionally tunnel device names)
 - Supports automatic replication of peer IP addresses
 - Supports automatic replication of network config updates
   - network config data is secure and protected by a Ed25519 signature
   - network config data replication is encrypted and only available to members of the network, even during bootstrap
 - Fully meshed (all nodes connect to each other directly unless configured otherwise)
 - Supports automatic VXLAN setup with multiple peers
   - automatically installs eBPF program to deal with MTU limitations and avoid fragmentation
 - Automatic setup of routes / IP addresses based on network config data
 - Supports direct connection through double-NAT, as long as the network has one node with a public IP address
 - Simple CLI for creating and updating networks between OpenWrt hosts with very few commands
 - Builds and runs on regular Linux distributions as well, and also macOS (with some limitations)
 - Automatically assigns an IPv6 address for each host, which is generated from the host public key
 - writes a host file containing entries for all configured hosts
   - can be used with dnsmasq for local lookup
   - configurable domain suffix
 - allows creating freeform service definitions, which allows services to query member IP addresses using ubus
 - Supports peer discovery via BitTorrent 'Mainline' DHT, which works even through double-NAT

## Building

### OpenWrt
 TBC

### Linux

The following build dependencies are required:

 - cmake, pkg-config
 - libelf-dev, zlib1g-dev, libjson-c-dev

To build:

```
git clone https://git.openwrt.org/project/unetd.git
cd unetd
./build.sh
```

## Example setup

### Preparation

This set of example commands assumes two OpenWRT routers with the IP addresses `192.168.1.13` and `192.168.1.15` which have **not** been configured for unetd yet, each has `unetd`, `unet-cli` and `unet-tool` installed. `vxlan` (and its implied `kmod-vxlan`) are also installed. The assumption here is that the local host, here say 192.168.1.2 has these installed, and also forms a unet node.

Note: `unetd` is not yet capable of installing these prerequisites above via `opkg`.

### Example

This creates a new JSON file `test.json` locally and also generates a signing key in `test.json.key` locally (if it doesn't exist already):

```
# unet-cli test.json create
```

Result:

```
test.json:
{
	"config": {
		"port": 51830,
		"keepalive": 10,
		"peer-exchange-port": 51831
	},
	"hosts": {
	},
	"services": {
	}
}
```

This creates a VXLAN tunnel definition in `test.json` and predicates hosts that are to be members of it via the `ap` group:

```
# unet-cli test.json add-service l2-tunnel type=vxlan members=@ap
```

Result:

```
test.json:
{
	...
	"services": {
		"l2-tunnel": {
			"config": {
			},
			"members": [
				"@ap"
			],
			"type": "vxlan"
		}
	}
}
```

This connects to 192.168.1.13 over SSH, and on 192.168.1.13, generates an unetd interface named `unet`, along with new host keys, puts in the signing key and also tells it to create the `vx0` VXLAN device connected to the `l2-tunnel` service description we created in the last command, storing its public key in the local `test.json`, along with its endpoint address `192.168.1.13`:

```
# unet-cli test.json add-ssh-host ap1 root@192.168.1.13 endpoint=192.168.1.13 tunnels=vx0:l2-tunnel groups=ap
```

Note: you will authenticate via SSH, either user:pass or key based, if that was set up in advance.

Result:

```
test.json:
{
	...
	"hosts": {
		"ap1": {
			"key": "....=",
			"endpoint": "192.168.1.13",
			"groups": [
				"ap"
			]
		}
	},
	...
}
```

This does the same for the other host:

```
# unet-cli test.json add-ssh-host ap2 root@192.168.1.15 endpoint=192.168.1.15 tunnels=vx0:l2-tunnel groups=ap
```

Result:

```
test.json:
{
	...
	"hosts": {
		...
		"ap2": {
			"key": "...=",
			"endpoint": "192.168.178.1",
			"groups": [
				"ap"
			]
		}
	},
	...
}
```

This signs the network data and uploads it to unetd running on 192.168.1.13:

```
# unet-cli test.json sign upload=192.168.1.13
```

By now, uploading the data to one of the two hosts is enough, because once it (192.168.1.13) has processed the update, it (192.168.1.13) will find the endpoint address of the other host (192.168.1.15) and sync the network data with it automatically. After that last command, the unetd network should be up on both sides, and the VXLAN tunnel created as well.

## Configuration

### UCI network interface

Configuration of a `interface` section in /etc/config/network for unetd.

|Name    |Type   |Required|Description                                                                                                       |
|--------|-------|--------|------------------------------------------------------------------------------------------------------------------|
|proto   |string |required|Needs to be unet                                                                                                  |
|device  |string |required|Name of the tunnel device                                                                                         |
|key     |string |required|Local wireguard key                                                                                               |
|auth_key|string |required|Key used to sign network config                                                                                   |
|tunnels |list   |        |List of tunnel devices mapped to VXLAN service definitions in the network config (format: <device>=<servicename>).|
|connect |list   |        |List of external unetd host IP addresses to download network config updates from                                  |
|domain  |string |        |Domain suffix for hosts in the generated hosts file                                                               |
|dht     |boolean|        |Enable DHT peer discovery for this network                                                                        |

The `connect` option only needs to be used for bootstrapping the setup in case you're not uploading the network data to the node directly. Once unetd has a working peer connection, it will always replicate updates over the tunnel.

### Network config data

Network config is written as a JSON file.

Example:

```
{
        "config": {
                "port": 51830,
                "keepalive": 10,
                "peer-exchange-port": 51831,
                "stun-servers": [
                        "stun.l.google.com:19302",
                        "stun1.l.google.com:19302"
                ]
        },
        "hosts": {
                "ap1": {
                        "key": "yB3V0Wz37qheZoZiG0KNFAqfuI2TetO4sfXgqO/Gd0c=",
                        "endpoint": "192.168.1.13",
                        "groups": [
                                "ap"
                        ]
                },
                "ap2": {
                        "key": "aGNcyMLrN+C4WW0nJBUGwqw8ifIleUVefv/9vh+d1Fw=",
                        "endpoint": "192.168.1.15",
                        "groups": [
                                "ap"
                        ]
                }
        },
        "services": {
                "l2-tunnel": {
                        "config": {
                        },
                        "members": [
                                "@ap"
                        ],
                        "type": "vxlan"
                }
        }
}
```

Config properties:

|Name              |Type            |Description                                                               |
|------------------|----------------|--------------------------------------------------------------------------|
|port              |int             |Wireguard tunnel port (can be overriden for individual hosts)             |
|keepalive         |int             |Interval (in seconds) for keepalive and forcing peer reconnection attempts|
|peer-exchange-port|int             |Port for exchanging peer messages on the WireGuard tunnel (0: disabled)   |
|stun-servers      |array of strings|List of STUN servers written as hostname:port strings                     |

Host properties:

|Name              |Type            |Description                                                                                                             |
|------------------|----------------|------------------------------------------------------------------------------------------------------------------------|
|key               |string          |Wireguard public key                                                                                                    |
|groups            |array of strings|Names of groups that the host is a member of                                                                            |
|ipaddr            |array of strings|Local IP addresses of the host (IPv4 or IPv6)                                                                           |
|subnet            |array of strings|Subnets routed by the host (IPv4 or IPv6) (format: <addr>/<mask>)                                                       |
|port              |int             |Wireguard tunnel port (overrides config property)                                                                       |
|peer-exchange-port|int             |Host specific port for exchanging peer messages on the WireGuard tunnel (0: disabled)                                   |
|endpoint          |string          |Public endpoint address (format: <addr> for IPv4, [<addr>] for IPv6 with optional :<port> suffix)                       |
|gateway           |string          |Name of another host to use as gateway (can be used for avoiding direct connections with all other peers from this host)|

Service properties

|Name   |Type            |Description                                              |
|-------|----------------|---------------------------------------------------------|
|type   |string          |Service type                                             |
|config |object          |Service type specific config options                     |
|members|array of strings|Members assigned to this service (use @<name> for groups)|

## CLI usage

```
Usage: unet-cli [<flags>] <file> <command> [<args>] [<option>=<value> ...]

     Commands:
      - create:                                 Create a new network file
      - set-config:                             Change network config parameters
      - add-host <name>:                        Add a host
      - add-ssh-host <name> <host>:             Add a remote OpenWrt host via SSH
                                                (<host> can contain SSH options as well)
      - set-host <name>:                        Change host settings
      - set-ssh-host <name> <host>:             Update local and remote host settings
      - add-service <name>:                     Add a service
      - set-service <name>:                     Change service settings
      - sign                                    Sign network data

     Flags:
      -p:                                       Print modified JSON instead of updating file

     Options:
      - config options (create, set-config):
        port=<val>                              set tunnel port (default: 51830)
        pex_port=<val>                          set peer-exchange port (default: 51831, 0: disabled)
        keepalive=<val>                         set keepalive interval (seconds, 0: off, default: 10)
        stun=[+|-]<host:port>[,<host:port>...]  set/add/remove STUN servers
      - host options (add-host, add-ssh-host, set-host):
        key=<val>                               set host public key (required for add-host)
        port=<val>                              set host tunnel port number
        pex_port=<val>                          set host peer-exchange port (default: network pex_port, 0: disabled)
        groups=[+|-]<val>[,<val>...]            set/add/remove groups that the host is a member of
        ipaddr=[+|-]<val>[,<val>...]            set/add/remove host ip addresses
        subnet=[+|-]<val>[,<val>...]            set/add/remove host announced subnets
        endpoint=<val>                          set host endpoint address
        gateway=<name>                          set host gateway (using name of other host)
     - ssh host options (add-ssh-host, set-ssh-host)
        auth_key=<key>                          use <key> as public auth key on the remote host
        priv_key=<key>                          use <key> as private host key on the remote host (default: generate a new key)
        interface=<name>                        use <name> as interface in /etc/config/network on the remote host
        domain=<name>                           use <name> as hosts file domain on the remote host (default: unet)
        connect=<val>[,<val>...]                set IP addresses that the host will contact for network updates
        tunnels=<ifname>:<service>[,...]        set active tunnel devices
     - service options (add-service, set-service):
        type=<val>                              set service type (required for add-service)
        members=[+|-]<val>[,<val>...]           set/add/remove service member hosts/groups
     - vxlan service options (add-service, set-service):
        id=<val>                                set VXLAN ID
        port=<val>                              set VXLAN port
        mtu=<val>                               set VXLAN device MTU
        forward_ports=[+|-]<val>[,<val>...]     set members allowed to receive broadcast/multicast/unknown-unicast
     - sign options:
        upload=<ip>[,<ip>...]                   upload signed file to hosts
```

## DHT support

For DHT peer discovery, the unet-dht package needs to be installed, and dht enabled in the interface on the nodes. For NAT support, you also need to configure at least one working STUN server in the network data. While peers can find each other through DHT directly, STUN is needed for figuring out the external wireguard port and establishing a network connection over it. Please note that DHT based discovery needs some time for peers to actually discover each other, sometimes 1-3 minutes.
