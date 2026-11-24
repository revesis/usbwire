#!/bin/bash
# Touch test: real FIDO operations that need a human touch, through usbwire.
#
#   SERVER=10.40.11.44:7443 scripts/touchtest.sh [ONE_WAY_MS]
#
# Needs: root, vhci-hcd loaded, the client paired with SERVER, libfido2 tools.
# Uses U2F (-u), so no PIN is needed even if the key has one.
# Touch the key when it blinks (twice: register, then sign).
# ONE_WAY_MS > 0 adds that much delay each way (WAN emulation via udpdelay).
set -u
B=$(cd "$(dirname "$0")/.." && pwd)/target/release
SERVER=${SERVER:?set SERVER=host:7443}
OW=${1:-0}
W=$(mktemp -d)
trap 'usbip detach -p 0 >/dev/null 2>&1; kill $CL ${UD:-} 2>/dev/null; wait 2>/dev/null; rm -rf "$W"' EXIT

server=$SERVER; certarg=
if [ "$OW" != 0 ]; then
  "$B/udpdelay" 127.0.0.1:7444 "$SERVER" "$OW" 2>/dev/null & UD=$!
  server=127.0.0.1:7444
  certarg="--cert $HOME/.config/usbwire/servers/$(echo "$SERVER" | sed 's/[^A-Za-z0-9.-]/_/g').der"
  sleep 0.3
fi
"$B/usbwire-client" serve --server "$server" $certarg --dev 1050:0407 > "$W/client.log" 2>&1 & CL=$!
sleep 1.5
usbip attach -r 127.0.0.1 -b 1-1 >/dev/null || { cat "$W/client.log"; exit 1; }
dev=; for _ in $(seq 100); do dev=$(fido2-token -L 2>/dev/null | cut -d: -f1 | head -1); [ -n "$dev" ] && break; sleep 0.05; done
[ -n "$dev" ] || { echo "no FIDO device appeared"; cat "$W/client.log"; exit 1; }
echo "remote key at $dev (added RTT: $((OW * 2)) ms)"

ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

# 1. Register (U2F): random challenge, test RP, random user id.
printf '%s\n' "$(head -c32 /dev/urandom | base64)" "usbwire.test" "tester" "$(head -c16 /dev/urandom | base64)" > "$W/cred_param"
echo ">>> touch the key now (register)"
t=$(date +%s%N)
fido2-cred -M -u -i "$W/cred_param" -o "$W/cred" "$dev" es256 || { echo "register FAILED"; exit 1; }
echo "register: ok in $(ms $t) ms (includes your reaction time)"
fido2-cred -V -i "$W/cred" -o "$W/pubkey" es256 >/dev/null || { echo "attestation verify FAILED"; exit 1; }
echo "attestation: verified"

# 2. Sign (U2F assertion) with the new credential, then verify the signature.
{ head -c32 /dev/urandom | base64; echo usbwire.test; sed -n 5p "$W/cred"; } > "$W/assert_param"
echo ">>> touch the key again (sign)"
t=$(date +%s%N)
fido2-assert -G -u -i "$W/assert_param" -o "$W/assert" "$dev" || { echo "sign FAILED"; exit 1; }
echo "sign: ok in $(ms $t) ms (includes your reaction time)"
fido2-assert -V -i "$W/assert" "$W/pubkey" es256 && echo "signature: verified with the registered public key"
echo "PASS"
