#!/bin/bash
# Usage: SERVER=host:7443 scripts/realbench.sh ONE_WAY_MS(0=direct) [client flags...]
# Attaches the remote FIDO key through vhci (run as root, vhci-hcd loaded) and
# times real `fido2-token -I` calls; ONE_WAY_MS>0 inserts udpdelay for WAN emulation.
S=${STATE:-/tmp}
# Uses the certificate stored by `usbwire-client pair`; CERT=file overrides it.
CERTARG=${CERT:+--cert $CERT}
B=$(cd "$(dirname "$0")/.." && pwd)/target/release
ow=$1; shift
server=${SERVER:?set SERVER=host:7443}
# With a delay relay the client dials 127.0.0.1:7444 but must still use the
# certificate paired for $SERVER.
PAIRED=$HOME/.config/usbwire/servers/$(echo "$SERVER" | sed 's/[^A-Za-z0-9.-]/_/g').der
if [ "$ow" != 0 ]; then $B/udpdelay 127.0.0.1:7444 $SERVER $ow 2>/dev/null & UD=$!; server=127.0.0.1:7444; CERTARG="--cert ${CERT:-$PAIRED}"; sleep 0.3; fi
$B/usbwire-client serve --server $server $CERTARG --dev 1050:0407 "$@" > $S/client-$ow.log 2>&1 & CL=$!
sleep 1.5
t0=$(date +%s%N); usbip attach -r 127.0.0.1 -b 1-1 >/dev/null 2>&1
dev=""; for i in $(seq 100); do dev=$(fido2-token -L 2>/dev/null | cut -d: -f1 | head -1); [ -n "$dev" ] && break; sleep 0.05; done
t1=$(date +%s%N)
printf "one-way %3sms %-16s attach->hidraw %5d ms | fido2-token -I:" "$ow" "${*:-early-ack}" $(( (t1-t0)/1000000 ))
for i in 1 2 3 4 5 6; do
  a=$(date +%s%N); if fido2-token -I $dev >/dev/null 2>&1; then printf " %4d" $(( ($(date +%s%N)-a)/1000000 )); else printf " FAIL"; fi
done; echo " ms"
usbip detach -p 0 >/dev/null 2>&1; sleep 0.5
kill $CL 2>/dev/null; wait $CL 2>/dev/null; [ -n "$UD" ] && { kill $UD; wait $UD 2>/dev/null; }
sleep 0.5
