#!/bin/bash
# Network outage test: the attached key must survive a dropped link without
# the OS seeing it unplugged.
#
#   SERVER=host:7443 scripts/outage.sh DOWN_SECONDS
#
# Runs the client through a udpdelay relay, checks the key with fidoping,
# kills the relay for DOWN_SECONDS (a FIDO request is issued 2 s into the
# outage), brings it back and checks again: same hidraw node, no USB
# disconnect in the kernel log, both fidoping runs OK.
# Needs root, vhci-hcd, fidoping, and the client paired with SERVER.
set -u
B=$(cd "$(dirname "$0")/.." && pwd)/target/release
SERVER=${SERVER:?set SERVER=host:7443}
DOWN=${1:?outage length in seconds}
W=$(mktemp -d)
CERT=$HOME/.config/usbwire/servers/$(echo "$SERVER" | sed 's/[^A-Za-z0-9.-]/_/g').der
relay() { "$B/udpdelay" 127.0.0.1:7444 "$SERVER" 1 2>/dev/null & UD=$!; }
cleanup() { kill -INT ${CL:-} 2>/dev/null; sleep 1; kill ${UD:-} ${FP:-} 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
now() { date +%T.%3N; }

relay; sleep 0.3
dmesg -C 2>/dev/null
"$B/usbwire-client" serve --server 127.0.0.1:7444 --cert "$CERT" --dev 1050:0407 --attach > "$W/client.log" 2>&1 & CL=$!
dev=; for _ in $(seq 120); do dev=$("$B/fidoping" list 2>/dev/null | grep hidraw); [ -n "$dev" ] && break; sleep 0.25; done
[ -n "$dev" ] || { echo "no FIDO device appeared"; cat "$W/client.log"; exit 1; }
sleep 1
echo "$(now) attached as $dev"
"$B/fidoping" -n 10 | grep -E "PING|OK|error"

echo "$(now) network down for $DOWN s"
kill $UD; wait $UD 2>/dev/null
sleep 2
echo "$(now) FIDO request during the outage"
( t=$(date +%s%N); "$B/fidoping" -n 1 > "$W/during.txt" 2>&1; echo "exit $? after $(( ($(date +%s%N) - t) / 1000000 )) ms" >> "$W/during.txt" ) & FP=$!
sleep $((DOWN - 2))
relay; echo "$(now) network back"
wait $FP; FP=
echo "--- request made during the outage:"; grep -E "INIT|PING|OK|error|exit" "$W/during.txt"
after=$("$B/fidoping" list 2>/dev/null | grep hidraw)
echo "--- after: $after"
"$B/fidoping" -n 10 | grep -E "PING|OK|error"
echo "--- kernel USB disconnects: $(dmesg | grep -c 'USB disconnect')"
echo "--- client log:"
sed 's/\x1b\[[0-9;]*m//g' "$W/client.log" | grep -E "WARN|lost|reconnect|resuming|ERROR" | cut -c12-23,29-200
[ "$after" = "$dev" ] && [ "$(dmesg | grep -c 'USB disconnect')" = 0 ] && echo "PASS: same device, never unplugged"
