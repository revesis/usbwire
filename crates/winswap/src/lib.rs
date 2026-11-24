//! Bind a USB device to the inbox WinUSB driver for export, and give it back
//! to its default drivers afterwards. Used by `usbwire-server` and by the
//! `winswap` command-line tool.

#[cfg(windows)]
pub mod swap;
