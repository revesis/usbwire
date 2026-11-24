# usbwire

Use a USB security key (YubiKey, other FIDO/HID dongles) plugged into one
machine from another machine, over the internet.

usbwire is USB/IP rebuilt for latency over WAN. It uses QUIC instead of
TCP, its own protocol between server and client, and mutual TLS with
one-time-code pairing. The client presents the device to the operating
system's own USB/IP driver, so applications (browsers, `libfido2`, `ssh`,
`gpg`) see an ordinary local key.

```
 Windows server                                   Client (Linux today)
 ┌──────────────────────────┐   QUIC / UDP 7443   ┌────────────────────────────┐
 │ YubiKey ── WinUSB        │◄═══════════════════►│ usbwire-client serve       │
 │ usbwire-server (service) │  mTLS, paired certs │   └─ USB/IP on 127.0.0.1   │
 └──────────────────────────┘                     │ vhci_hcd ── /dev/hidrawN   │
                                                  └────────────────────────────┘
```

| Status | |
|---|---|
| Server | Windows 10/11 (also runs on Linux for development) |
| Client | Linux (vhci_hcd). Windows through usbip-win2 is planned; macOS later |
| Devices | Exports Yubico devices (VID `1050`) by default; configurable |

## Why not plain USB/IP?

On a WAN link, plain USB/IP round-trips every USB transfer. FIDO keys talk
CTAPHID: small 64-byte interrupt reports, with a timeout between the packets
of one message. usbwire hides the round trip where USB semantics allow:

- **Early interrupt OUT ack.** The client completes an interrupt OUT to the
  host straight away and sends the data on. Without it, multi-packet CTAP
  messages fail with `CTAPHID_ERR_MSG_TIMEOUT` once RTT reaches about 20 ms.
- **Interrupt IN push.** The server keeps reads pending on the device and
  pushes reports as they arrive. The client buffers them, so the host's next
  poll is answered locally.
- **Descriptor cache.** Descriptors are sent once at attach and answered
  locally after that, which speeds up enumeration.

Each USB endpoint has its own QUIC stream, so a slow transfer on one does not
hold up another.

Measured with a YubiKey 5 at an added 100 ms RTT:

| | plain forwarding | usbwire |
|---|---|---|
| 1 KB CTAPHID_PING | 2.08 s | 0.19 s |
| `fido2-token -I` (6 CTAP requests) | 1.54 s | 0.76 s |
| attach + enumerate | 2.38 s | 1.25 s |

## Security

- **Identities.** Each server and client creates a self-signed certificate on
  first run. Peers are identified by the SHA-256 fingerprint of that
  certificate; no CA is involved.
- **Pairing.** `usbwire-server pair` shows a one-time code (`XXXXX-XXXXX`),
  valid for 10 minutes, for one use, with at most 3 wrong attempts. The code
  is the password of a SPAKE2 exchange, so an eavesdropper or a
  man-in-the-middle cannot test guesses offline. The confirmation is bound
  to both certificate fingerprints. After pairing, the client pins the
  server's certificate.
- **Access control.** The server offers only devices that match `export` in
  its config, and each client sees only the devices on its own allow list.
  A device is held by one client at a time. When the same client reconnects,
  it takes over its own stale session.
- **Audit log.** Pairings, rejections, sessions, attaches and detaches go to
  `audit.log`, one line each.

## Windows driver handling

To read a device from user space, the server binds it to Windows' inbox
WinUSB driver while a client is attached. When the device is released, the
server gives it back to its normal drivers after a 5 second grace period, so
a quick reconnect doesn't swap drivers back and forth.

Each swap is recorded in a journal
(`%ProgramData%\usbwire\winswap-journal.tsv`). If the server crashes while a
device is swapped, it restores the device on its next start. Stopping the
service also restores every swapped device.

## Build

The workspace uses Rust edition 2024, so it needs Rust 1.85 or newer.

```sh
cargo build --release                                  # Linux client (and server)
cargo build --release --target x86_64-pc-windows-gnu   # Windows server, cross-compiled
```

To cross-compile from Linux, install `mingw-w64-gcc` and run
`rustup target add x86_64-pc-windows-gnu`.

| Crate | What it is |
|---|---|
| `proto` | Wire messages (postcard) and length-prefixed framing |
| `net` | QUIC setup, certificates, pinning verifiers, SPAKE2 pairing |
| `server` | `usbwire-server`: registry, endpoint forwarding, state, Windows service |
| `client` | `usbwire-client`: QUIC client and local USB/IP adapter |
| `winswap` | WinUSB swap and restore through SetupAPI, plus a debugging CLI |
| `udpdelay` | UDP relay that adds a fixed delay, for WAN tests |

## Setup

### 1. Server (Windows, as Administrator)

```bat
usbwire-server service install
```

This installs the `usbwire` service (automatic start, LocalSystem), starts it,
and creates `C:\ProgramData\usbwire\config.json`. Allow UDP 7443 through the
firewall if clients connect from other machines.

To try the server without installing a service, run it in a console:
`usbwire-server run`.

### 2. Pair a client

On the server:

```bat
usbwire-server pair --name laptop --allow 1050:0407
```

```
Pairing code:  7K3QD-M9XAB
Valid for 10 minutes, one use, 3 wrong attempts max.
Allows:        1050:0407
Server key:    22b17cded9cbe47e
```

On the client:

```sh
usbwire-client pair --server SERVER_HOST:7443 --code 7K3QD-M9XAB
```

Check that the server key fingerprint printed on the client matches the one
on the server.

### 3. Use the key (Linux client)

```sh
sudo modprobe vhci-hcd
usbwire-client list  --server SERVER_HOST:7443
usbwire-client serve --server SERVER_HOST:7443 --dev 1050:0407 &
sudo usbip attach -r 127.0.0.1 -b 1-1
fido2-token -L       # the remote key is now a local /dev/hidrawN
```

To detach, run `sudo usbip detach -p 0` or stop the client. The server gives
the device back to its Windows drivers a few seconds later.

## Commands

### `usbwire-server`

```
usbwire-server [run]                              serve in the foreground
usbwire-server pair [--name NAME] [--allow SEL,..] open a one-time pairing
usbwire-server clients                            list paired clients
usbwire-server revoke NAME|FINGERPRINT            remove a client
usbwire-server service install|uninstall          Windows service (as Administrator)
options: --state DIR  --listen ADDR:PORT
```

`pair`, `clients` and `revoke` change files in the state directory, so they
take effect on a running server or service. Sessions that are already open
when a client is revoked stay up until they disconnect.

### `usbwire-client`

```
usbwire-client pair  --server HOST:PORT --code CODE
usbwire-client list  --server HOST:PORT
usbwire-client serve --server HOST:PORT --dev VID:PID [--listen 127.0.0.1:3240]
usbwire-client bench --server HOST:PORT --dev VID:PID [-n 200]
options: --state DIR  --cert FILE
         --no-early-ack  --no-push  --no-desc-cache   (turn off one optimisation, for comparison)
```

The client's state is in `~/.config/usbwire` (Linux) or `%APPDATA%\usbwire`
(Windows).

## Configuration

`config.json` in the server state directory (`C:\ProgramData\usbwire` on
Windows):

```json
{
  "listen": "0.0.0.0:7443",
  "export": ["1050:*"],
  "restore_on_release": true,
  "restore_delay_secs": 5
}
```

Selectors are hex `VID:PID`, `VID:*` or `*`.

The server state directory holds:

| File | Contents |
|---|---|
| `cert.der`, `key.der` | Server identity. Keep `key.der` private |
| `clients.json` | Paired clients: fingerprint, name, allow list |
| `pending-pair.json` | The open pairing code, if any |
| `audit.log` | Security events |
| `server.log` | Service log |

## Testing

```sh
cargo test
cargo clippy --all-targets
cargo clippy --all-targets --target x86_64-pc-windows-gnu
```

Hardware tests (Linux client, run as root, `vhci-hcd` loaded, paired with the
server). `ONE_WAY_MS` adds that much delay in each direction through
`udpdelay`.

```sh
SERVER=host:7443 scripts/realbench.sh ONE_WAY_MS     # times fido2-token -I
SERVER=host:7443 scripts/touchtest.sh [ONE_WAY_MS]   # U2F register + sign; needs two touches
```

## Roadmap

- Windows client through usbip-win2
- Tray app for the server (status, pairing code)
- End open sessions when a client is revoked
- Report errors on early-acked OUT transfers back to the host
- NAT traversal
- macOS client
