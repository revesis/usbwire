//! Android JNI entry point. The bridge app opens the Proxmark3 with
//! `UsbManager` (no root), gets its usbdevfs fd from
//! `UsbDeviceConnection.getFileDescriptor()`, and calls `startServer` here to
//! run the usbwire QUIC server in-process over that fd (`--from-fd`). Running
//! in-process avoids handing the fd across `exec` (Android's ProcessBuilder
//! closes child fds). Logs go to `<stateDir>/server.log`, which the app tails.

use std::future::pending;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jint;

use crate::server;
use crate::state::State;

static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

fn init_logging(state_dir: &str) {
    let appender = tracing_appender::rolling::never(state_dir, "server.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    if LOG_GUARD.set(guard).is_err() {
        return; // already initialised
    }
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer)
        .try_init();
}

/// `Native.startServer(fd, stateDir, listen)` — blocks running the server until
/// the process ends. Returns 0 on a clean shutdown, negative on error. The app
/// calls this on a dedicated background thread.
///
/// JNI name: package `com.pm3.bridge`, class `Native`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_pm3_bridge_Native_startServer(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    state_dir: JString,
    listen: JString,
) -> jint {
    let state_dir: String = match env.get_string(&state_dir) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let listen_str: String = env.get_string(&listen).map(Into::into).unwrap_or_default();

    init_logging(&state_dir);

    let listen: Option<SocketAddr> = if listen_str.is_empty() {
        None
    } else {
        match listen_str.parse() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::error!("bad listen address {listen_str:?}: {e}");
                return -2;
            }
        }
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("creating tokio runtime: {e}");
            return -3;
        }
    };

    tracing::info!(fd, ?listen, state = %state_dir, "starting usbwire server from Android fd");
    let result = rt.block_on(async move {
        let state = Arc::new(State::open(Path::new(&state_dir))?);
        server::run(state, listen, Some(fd), pending::<()>()).await
    });
    match result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("server exited: {e:#}");
            -4
        }
    }
}
