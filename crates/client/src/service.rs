//! Windows service: run `serve --attach` in the background from boot.
//!
//!   usbwire-client service install --server HOST:PORT --dev VID:PID [serve options]
//!   usbwire-client service uninstall
//!
//! `install` checks that this client is paired with the server, then
//! registers the service (automatic start, LocalSystem, which usbip-win2
//! needs to attach) with the same state directory, and starts it. The
//! service reconnects by itself, so it also covers a server that is not
//! reachable yet at boot. Logs go to <state>\client.log.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::watch;
use tracing::{error, info};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::Args;

pub const NAME: &str = "usbwire-client";
const DISPLAY_NAME: &str = "usbwire client (remote USB security key)";

const USAGE: &str = "usage: usbwire-client service install --server HOST:PORT --dev VID:PID [serve options]\n       usbwire-client service uninstall";

/// Serve options the service was started with (from its command line).
static OPTIONS: OnceLock<Vec<String>> = OnceLock::new();

pub fn main(rest: &[String]) -> Result<()> {
    match rest.first().map(String::as_str) {
        Some("install") => install(&rest[1..]),
        Some("uninstall") => uninstall(),
        Some("run") => {
            OPTIONS.set(rest[1..].to_vec()).ok();
            service_dispatcher::start(NAME, ffi_service_main).context("not started by the service manager")?;
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

/// `serve` options as the service runs them: always with --attach (there is
/// nobody to run usbip by hand).
fn serve_args(opts: &[String]) -> Result<Args> {
    let mut raw = vec!["serve".to_string()];
    raw.extend(opts.iter().cloned());
    let mut a = crate::parse_args(raw)?;
    a.auto_attach = true;
    Ok(a)
}

/// The command line to store: path options made absolute (the service runs
/// in System32), the state directory pinned, --attach added.
fn launch_options(opts: &[String], state: &std::path::Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        match o.as_str() {
            "--state" => {
                it.next();
            }
            "--cert" => {
                let v = it.next().context("--cert needs a value")?;
                out.push(o.clone());
                out.push(std::path::absolute(v)?.to_string_lossy().into_owned());
            }
            "--attach" => {}
            _ => out.push(o.clone()),
        }
    }
    out.extend(["--state".to_string(), state.to_string_lossy().into_owned(), "--attach".to_string()]);
    Ok(out)
}

fn install(opts: &[String]) -> Result<()> {
    let args = serve_args(opts)?;
    let state = std::path::absolute(&args.state)?;
    let cert = match &args.cert {
        Some(c) => std::path::absolute(c)?,
        None => crate::server_cert_path(&state, &args.server),
    };
    if !cert.exists() {
        bail!("not paired with {} (no {}): run `usbwire-client pair` first", args.server, cert.display());
    }

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
        .context("opening the service manager (run as Administrator)")?;
    let mut launch: Vec<OsString> = vec!["service".into(), "run".into()];
    launch.extend(launch_options(opts, &state)?.into_iter().map(OsString::from));
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: launch,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating the service")?;
    service.set_description(format!("Attaches a USB device exported by usbwire server {} to this computer.", args.server))?;
    service.start::<&str>(&[]).context("starting the service")?;
    println!("installed and started service {NAME:?}; log in {}", state.join("client.log").display());
    Ok(())
}

fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run as Administrator)")?;
    let service = manager
        .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .context("opening the service")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        for _ in 0..40 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete()?;
    println!("service {NAME:?} removed");
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let opts = OPTIONS.get().cloned().unwrap_or_default();
    let args = match serve_args(&opts) {
        Ok(a) => a,
        Err(_) => return, // nowhere to log yet; the SCM reports the service stopped
    };
    if let Ok(file) = std::fs::create_dir_all(&args.state)
        .and_then(|_| OpenOptions::new().create(true).append(true).open(args.state.join("client.log")))
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
            )
            .with_ansi(false)
            .with_writer(Mutex::new(file))
            .try_init();
    }
    if let Err(e) = run_service(args) {
        error!("service failed: {e:#}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, wait_hint: Duration, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: if exit == 0 { ServiceExitCode::Win32(0) } else { ServiceExitCode::ServiceSpecific(exit) },
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

fn run_service(args: Args) -> Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = service_control_handler::register(NAME, move |ctl| match ctl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::ZERO,
        0,
    ))?;
    info!(server = %args.server, "service started");

    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        // Tell the SCM we are on our way out while the connection closes.
        let mut pending = stop_rx.clone();
        tokio::spawn(async move {
            let _ = pending.wait_for(|s| *s).await;
            let _ = handle.set_service_status(status(
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                Duration::from_secs(10),
                0,
            ));
        });
        crate::run(args, stop_rx).await
    });
    match &result {
        Ok(()) => info!("service stopped"),
        Err(e) => error!("serve: {e:#}"),
    }
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
        u32::from(result.is_err()),
    ))?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_command_line() {
        let opts: Vec<String> =
            ["--server", "h:7443", "--state", "rel", "--attach", "--dev", "1050:0407"].map(String::from).to_vec();
        let out = launch_options(&opts, std::path::Path::new("C:\\st")).unwrap();
        assert_eq!(out, ["--server", "h:7443", "--dev", "1050:0407", "--state", "C:\\st", "--attach"]);
    }
}
