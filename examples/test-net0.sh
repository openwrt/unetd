#!/bin/sh
ifname="${1:-wg0}"
host="${2:-ap1}"

ip link add dev $ifname type wireguard > /dev/null 2>&1

# [ "$ifname" != "net0" ] && ln -sf net0.bin "${ifname}.bin"

../unetd -D $PWD -d -h $PWD/hosts -N '{
	"name": "'"$ifname"'",
	"type": "dynamic",
	"auth_key": "'"$(cat ./net0.pub)"'",
	"key": "'"$(cat ./net0-${host}.key)"'",
	"file": "'"$PWD/net0.json"'",
	"tunnels": {
		"vx0": "l2-tunnel"
	},
	"update-cmd": "'"$PWD/../scripts/update-cmd.pl"'"
}'
