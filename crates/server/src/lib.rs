//! usbwire-server as a library, so the binary (`main.rs`) and the Android
//! bridge app (JNI, `jni.rs`) share one implementation. The server exports
//! local USB devices over QUIC; on Android the device arrives as an already-open
//! usbdevfs fd via `server::run(.., from_fd, ..)` instead of enumeration.

pub mod device;
pub mod endpoint;
pub mod server;
pub mod state;

#[cfg(windows)]
pub mod service;

#[cfg(target_os = "android")]
mod jni;
