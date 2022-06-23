#!/bin/sh
ifname="${1:-wg0}"
host="${2:-ap1}"

ip link add dev $ifname type wireguard > /dev/null 2>&1

../unetd -d -h $PWD/hosts -N '{
	"name": "'"$ifname"'",
	"type": "file",
	"key": "'"$(cat ./net0-${host}.key)"'",
	"file": "'"$PWD/net0.json"'",
	"tunnels": {
		"vx0": "l2-tunnel"
	},
	"update-cmd": "'"$PWD/../scripts/update-cmd.pl"'"
}'
