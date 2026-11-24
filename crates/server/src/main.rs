//! usbwire-server: exports local USB devices over QUIC.
//!
//!   usbwire-server [run] [--state DIR] [--listen ADDR:PORT]
//!   usbwire-server pair [--name NAME] [--allow SEL,SEL...]   one-time code for a new client
//!   usbwire-server clients                                   list paired clients
//!   usbwire-server revoke NAME|FINGERPRINT
//!   usbwire-server service install|uninstall                 (Windows, as Administrator)
//!
//! Selectors are hex "VID:PID", "VID:*" or "*". Devices offered at all are set
//! by `export` in <state>/config.json; a client's allow list narrows that.

mod device;
mod endpoint;
mod server;
mod state;
#[cfg(windows)]
mod service;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use usbwire_net::auth;

use crate::state::State;

struct Args {
    cmd: Vec<String>,
    state: PathBuf,
    listen: Option<SocketAddr>,
    name: String,
    allow: Vec<String>,
}

const USAGE: &str = "usage: usbwire-server [run|pair|clients|revoke WHO|service install|service uninstall] \
[--state DIR] [--listen ADDR:PORT] [--name NAME] [--allow SEL,...]";

fn parse_args() -> Result<Args> {
    let mut a = Args { cmd: vec![], state: state::default_dir(), listen: None, name: String::new(), allow: vec![] };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--state" => a.state = val()?.into(),
            "--listen" => a.listen = Some(val()?.parse()?),
            "--name" => a.name = val()?,
            "--allow" => a.allow = val()?.split(',').map(|s| s.trim().to_string()).collect(),
            "-h" | "--help" => bail!("{USAGE}"),
            s if s.starts_with("--") => bail!("unknown option {s}\n{USAGE}"),
            _ => a.cmd.push(arg),
        }
    }
    Ok(a)
}

fn init_console_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let cmd: Vec<&str> = args.cmd.iter().map(String::as_str).collect();
    match cmd.as_slice() {
        [] | ["run"] => {
            init_console_logging();
            let state = Arc::new(State::open(&args.state)?);
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(state, args.listen, async {
                let _ = tokio::signal::ctrl_c().await;
            }))
        }
        ["pair"] => pair(&args),
        ["clients"] => {
            let state = State::open(&args.state)?;
            let clients = state.clients()?;
            if clients.is_empty() {
                println!("no paired clients");
            }
            for c in clients {
                println!("{:<20} {}  allow={:?}  paired {}", c.name, auth::short_fp(&c.fingerprint), c.allow, c.paired_at);
            }
            Ok(())
        }
        ["revoke", who] => {
            let state = State::open(&args.state)?;
            let gone = state.revoke(who)?;
            if gone.is_empty() {
                bail!("no client named or with fingerprint {who:?}");
            }
            for c in gone {
                state.audit(&format!("revoked client={} fp={}", c.name, auth::short_fp(&c.fingerprint)));
                println!("revoked {} ({})", c.name, auth::short_fp(&c.fingerprint));
            }
            println!("(a running server closes this client's open sessions within a few seconds)");
            Ok(())
        }
        #[cfg(windows)]
        ["service", "install"] => service::install(&args.state),
        #[cfg(windows)]
        ["service", "uninstall"] => service::uninstall(),
        #[cfg(windows)]
        ["service", "run"] => service::run_dispatcher(args.state),
        _ => bail!("{USAGE}"),
    }
}

fn pair(args: &Args) -> Result<()> {
    let state = State::open(&args.state)?;
    let identity = usbwire_net::load_or_create_identity(&state.dir)?;
    let allow = if args.allow.is_empty() { state.config()?.export } else { args.allow.clone() };
    let p = state.start_pairing(&args.name, allow)?;
    state.audit(&format!("pairing opened name={:?} allow={:?}", p.name, p.allow));
    println!("Pairing code:  {}", p.code);
    println!("Valid for {} minutes, one use, {} wrong attempts max.", state::PAIRING_TTL.as_secs() / 60, state::PAIRING_MAX_FAILURES);
    println!("Allows:        {}", p.allow.join(", "));
    println!("Server key:    {}", auth::short_fp(&auth::fingerprint(&identity.0)));
    println!();
    println!("On the client:  usbwire-client pair --server <this-host>:{} --code {}", usbwire_net::DEFAULT_PORT, p.code);
    Ok(())
}
