#!/bin/sh
ifname="${1:-wg0}"
host="${2:-ap1}"

../unetd -d -h $PWD/hosts -N '{
	"name": "'"$ifname"'",
	"type": "file",
	"key": "'"$(cat ./net0-${host}.key)"'",
	"file": "'"$PWD/net0.json"'",
	"update-cmd": "'"$PWD/../scripts/update-cmd.pl"'"
}'
