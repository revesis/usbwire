# usbwire

Use a USB security key (YubiKey, other FIDO/HID dongles) plugged into one
machine from another machine, over the internet.

usbwire is USB/IP rebuilt for latency over WAN. It uses QUIC instead of
TCP, its own protocol between server and client, and mutual TLS with
one-time-code pairing. The client presents the device to the operating
system's own USB/IP driver, so applications (browsers, `libfido2`, `ssh`,
`gpg`) see an ordinary local key.

```
 Windows server                                   Client (Linux or Windows)
 ┌──────────────────────────┐   QUIC / UDP 7443   ┌──────────────────────────────┐
 │ YubiKey ── WinUSB        │◄═══════════════════►│ usbwire-client serve         │
 │ usbwire-server (service) │  mTLS, paired certs │   └─ USB/IP on 127.0.0.1     │
 └──────────────────────────┘                     │ vhci_hcd / usbip-win2 driver │
                                                  │   └─ an ordinary local key   │
                                                  └──────────────────────────────┘
```

| Status | |
|---|---|
| Server | Windows 10/11 (also runs on Linux for development) |
| Client | Linux (vhci_hcd) and Windows 10/11 ([usbip-win2](https://github.com/vadimgrn/usbip-win2) driver). macOS later |
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
| 1 KB CTAPHID_PING, Linux client | 2.08 s | 0.19 s |
| 1 KB CTAPHID_PING, Windows client | fails (`CTAPHID_ERR_MSG_TIMEOUT`) | 0.19 s |
| `fido2-token -I` (6 CTAP requests), Linux | 1.54 s | 0.76 s |
| attach until the key is usable, Windows | 4.5 s | 1.7 s |

With no added delay, the Windows client is as fast as the key plugged in
directly: CTAPHID_INIT p50 4.00 ms both ways, 1 KB PING 72 ms both ways.

## Surviving connection loss

`usbwire-client serve` keeps the device attached to the OS while the
connection to the server comes and goes. Applications keep their handles
(`/dev/hidrawN`, Windows HID handles); the OS never sees an unplug.

- **Outages shorter than 10 s** are ridden out by QUIC: it retransmits, and
  nothing is lost. A request made during the outage completes once the
  link is back.
- **Longer outages, laptop sleep, server restarts:** the client notices
  within 10 s and reconnects, retrying every few seconds. It attaches the
  same device again (same VID:PID and serial number) and checks that its
  descriptors are unchanged, then resumes.
  - Interrupt IN reads simply keep waiting, like a device with nothing to say.
  - Transfers the server had when the link died fail with `EPROTO`. Nobody
    can know whether the device saw them, and replaying them could run a
    FIDO operation twice, so the application retries instead.
  - Transfers made while there is no connection are held, and sent after
    the reconnect.
- **When it stops retrying:** if the server refuses for good (not paired,
  revoked, version mismatch), if the device on the server has changed, or
  if another session of the same client took the device. Without that last
  check, two copies of one client would take it from each other forever.

`--no-reconnect` restores the old behaviour: exit when the connection drops.

Measured: after a server restart, the Linux client resumed in 3.9 s and the
Windows client in 2.9 s. After a 45 s network outage, the client
reconnected 4.9 s after the network returned. In both cases the OS kept the
same device, with no unplug.

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
| `fidoping` | Times CTAPHID INIT and 1 KB PING through the OS HID stack (Windows, Linux); no touch needed |

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

### 3a. Use the key: Linux client

```sh
sudo modprobe vhci-hcd
usbwire-client list  --server SERVER_HOST:7443
sudo usbwire-client serve --server SERVER_HOST:7443 --dev 1050:0407 --attach
fido2-token -L       # the remote key is now a local /dev/hidrawN
```

`--attach` runs `usbip attach` for you once the adapter listens. Without it,
the adapter listens on 127.0.0.1:3240 and you run
`sudo usbip attach -r 127.0.0.1 -b 1-1` yourself.

### 3b. Use the key: Windows client

1. Install [usbip-win2](https://github.com/vadimgrn/usbip-win2/releases)
   (0.9.8.1 or later). Its drivers are Microsoft-signed, so this works with
   Secure Boot on and test signing off. The installer briefly restarts all
   USB hubs.
2. Pair as above, then in an Administrator console:

```bat
usbwire-client serve --server SERVER_HOST:7443 --dev 1050:0407 --attach
```

The key appears with all its interfaces: FIDO, the OTP keyboard, and the
CCID smart card reader. `--attach`
picks a free local port, since 3240 is often taken (for example by
usbipd-win), and asks usbip-win2 for a single attach attempt, so the device
goes away when the client stops.

Stop with Ctrl-C: the client closes the connection cleanly, and the server
gives the device back to its own drivers a few seconds later. If the client
is killed instead, the server notices after its 10 s idle timeout.

### 4. Keep the key attached in the background

**Windows:** install the client as a service, in an Administrator console,
after pairing:

```bat
usbwire-client service install --server SERVER_HOST:7443 --dev 1050:0407
```

The service starts with Windows (LocalSystem, as usbip-win2 needs to
attach) and runs `serve --attach` with reconnect. It uses the state folder
you paired from (`%APPDATA%\usbwire` unless `--state` says otherwise) and
logs to `client.log` there. `install` refuses if that folder is not paired
with the server. `sc stop usbwire-client` detaches the key cleanly;
`usbwire-client service uninstall` removes the service.

**Linux:** use the systemd unit in
[`contrib/usbwire-client.service`](contrib/usbwire-client.service). Pair as
root into the state directory it uses, edit the server and device, then
`systemctl enable --now usbwire-client`:

```sh
sudo usbwire-client pair --state /var/lib/usbwire-client --server SERVER_HOST:7443 --code XXXXX-XXXXX
```

The unit loads `vhci-hcd` first. It exits only on errors that retrying
cannot fix, and systemd then tries again after 30 s.

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
usbwire-client serve --server HOST:PORT --dev VID:PID [--listen ADDR] [--attach] [--no-reconnect]
usbwire-client bench --server HOST:PORT --dev VID:PID [-n 200]
usbwire-client service install <serve options>       (Windows, as Administrator)
usbwire-client service uninstall
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
fidoping                                             # INIT + 1 KB PING on the attached key
SERVER=host:7443 scripts/outage.sh DOWN_SECONDS      # cut the network; the key must survive
```

Windows client, in an Administrator console, from the folder with the
binaries (the client must be paired with the server):

```bat
powershell -ExecutionPolicy Bypass -File wintest.ps1 -Server HOST:7443 [-OneWayMs 50]
```

The server also skips devices that are themselves attached over USB/IP
(below usbip-win2's or vhci_hcd's host controller). That makes it safe to run
the server and a client on the same machine, which is how the Windows client
was tested.

## Roadmap

- Tray app for the server (status, pairing code)
- End open sessions when a client is revoked
- Report errors on early-acked OUT transfers back to the host
- NAT traversal
- macOS client
