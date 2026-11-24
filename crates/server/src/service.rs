//! Windows service: `usbwire-server service install` registers the binary
//! with the Service Control Manager (automatic start, LocalSystem, which the
//! driver swap needs); the SCM then runs `usbwire-server service run`.
//! Logs go to <state>/server.log.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::state::State;

pub const NAME: &str = "usbwire";
const DISPLAY_NAME: &str = "usbwire USB forwarding server";
const DESCRIPTION: &str = "Exports selected USB devices (security keys) to paired usbwire clients over QUIC.";

static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn install(state: &Path) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
        .context("opening the service manager (run as Administrator)")?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["service".into(), "run".into(), "--state".into(), state.as_os_str().to_owned()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating the service")?;
    service.set_description(DESCRIPTION)?;
    State::open(state)?; // create config.json so it can be edited before first start
    service.start::<&str>(&[]).context("starting the service")?;
    println!("installed and started service {NAME:?}; state in {}", state.display());
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run as Administrator)")?;
    let service = manager
        .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .context("opening the service")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        // Stopping restores swapped drivers, which takes a few seconds.
        for _ in 0..60 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    service.delete()?;
    println!("service {NAME:?} removed (state directory kept)");
    Ok(())
}

pub fn run_dispatcher(state: PathBuf) -> Result<()> {
    STATE_DIR.set(state).ok();
    service_dispatcher::start(NAME, ffi_service_main).context("not started by the service manager")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let dir = STATE_DIR.get().cloned().unwrap_or_else(crate::state::default_dir);
    if let Ok(file) = std::fs::create_dir_all(&dir).and_then(|_| {
        OpenOptions::new().create(true).append(true).open(dir.join("server.log"))
    }) {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
            )
            .with_ansi(false)
            .with_writer(Mutex::new(file))
            .try_init();
    }
    if let Err(e) = run_service(dir) {
        error!("service failed: {e:#}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

fn run_service(dir: PathBuf) -> Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
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
    ))?;
    info!("service started");

    let state = Arc::new(State::open(&dir)?);
    let rt = tokio::runtime::Runtime::new()?;
    let mut stop = stop_rx;
    let result = rt.block_on(crate::server::run(state, None, async move {
        let _ = stop.wait_for(|s| *s).await;
        // Restoring drivers on the way out can take a few seconds.
        let _ = handle.set_service_status(status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            Duration::from_secs(30),
        ));
    }));
    if let Err(e) = &result {
        error!("server: {e:#}");
    }
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::ZERO))?;
    result
}
