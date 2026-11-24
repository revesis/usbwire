//! Server state directory: configuration, paired clients, pending pairing,
//! audit log. Plain files, re-read when needed, so `usbwire-server pair` and
//! `revoke` take effect on a running server (or service) without a restart.
//!
//!   config.json        listen address, export selectors, driver policy
//!   cert.der key.der   server identity
//!   clients.json       paired clients: fingerprint, name, allow list
//!   pending-pair.json  the one open pairing (one-time code), if any
//!   audit.log          one line per security-relevant event
//!   server.log         log file when running as a service

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

pub const PAIRING_TTL: Duration = Duration::from_secs(10 * 60);
pub const PAIRING_MAX_FAILURES: u32 = 3;

pub fn default_dir() -> PathBuf {
    if let Ok(d) = std::env::var("USBWIRE_STATE") {
        return d.into();
    }
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("usbwire")
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/var/lib".into());
        PathBuf::from(home).join(".local/state/usbwire-server")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    /// Devices this server offers, as selectors: "VID:PID", "VID:*" or "*" (hex).
    pub export: Vec<String>,
    /// Windows: give a device back to its normal drivers when no client uses it.
    pub restore_on_release: bool,
    /// Seconds to wait before restoring, so a quick reconnect doesn't churn drivers.
    pub restore_delay_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([0, 0, 0, 0], usbwire_net::DEFAULT_PORT)),
            // Security keys are the use case; anything else must be added deliberately.
            export: vec!["1050:*".into()],
            restore_on_release: true,
            restore_delay_secs: 5,
        }
    }
}

/// "VID:PID", "VID:*" or "*", hex, case-insensitive.
pub fn selector_matches(sel: &str, vid: u16, pid: u16) -> bool {
    let sel = sel.trim().to_ascii_lowercase();
    if sel == "*" {
        return true;
    }
    let Some((v, p)) = sel.split_once(':') else { return false };
    let hex = |s: &str| u16::from_str_radix(s, 16).ok();
    hex(v) == Some(vid) && (p == "*" || hex(p) == Some(pid))
}

pub fn any_matches(sels: &[String], vid: u16, pid: u16) -> bool {
    sels.iter().any(|s| selector_matches(s, vid, pid))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub fingerprint: String,
    pub name: String,
    /// Selectors of devices this client may list and attach.
    pub allow: Vec<String>,
    pub paired_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPair {
    pub code: String,
    pub name: String,
    pub allow: Vec<String>,
    pub expires_unix: u64,
    pub failures: u32,
}

pub struct State {
    pub dir: PathBuf,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn timestamp() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

impl State {
    pub fn open(dir: &Path) -> Result<State> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let s = State { dir: dir.to_path_buf() };
        if !s.path("config.json").exists() {
            s.save_json("config.json", &Config::default())?;
        }
        Ok(s)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn load_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        match fs::read(self.path(name)) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| format!("parsing {name}"))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save_json<T: Serialize>(&self, name: &str, v: &T) -> Result<()> {
        write_atomic(&self.path(name), &serde_json::to_vec_pretty(v)?)
    }

    pub fn config(&self) -> Result<Config> {
        Ok(self.load_json("config.json")?.unwrap_or_default())
    }

    pub fn clients(&self) -> Result<Vec<Client>> {
        Ok(self.load_json("clients.json")?.unwrap_or_default())
    }

    pub fn client(&self, fingerprint: &str) -> Result<Option<Client>> {
        Ok(self.clients()?.into_iter().find(|c| c.fingerprint == fingerprint))
    }

    pub fn add_client(&self, c: Client) -> Result<()> {
        let mut all = self.clients()?;
        all.retain(|x| x.fingerprint != c.fingerprint);
        all.push(c);
        self.save_json("clients.json", &all)
    }

    /// Remove by name or fingerprint prefix; returns the removed clients.
    pub fn revoke(&self, who: &str) -> Result<Vec<Client>> {
        let all = self.clients()?;
        let (gone, keep): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|c| c.name == who || (who.len() >= 8 && c.fingerprint.starts_with(&who.to_ascii_lowercase())));
        self.save_json("clients.json", &keep)?;
        Ok(gone)
    }

    pub fn start_pairing(&self, name: &str, allow: Vec<String>) -> Result<PendingPair> {
        let p = PendingPair {
            code: usbwire_net::auth::new_pairing_code()?,
            name: name.into(),
            allow,
            expires_unix: now_unix() + PAIRING_TTL.as_secs(),
            failures: 0,
        };
        self.save_json("pending-pair.json", &p)?;
        Ok(p)
    }

    /// The open pairing, if it has not expired.
    pub fn pending_pairing(&self) -> Result<Option<PendingPair>> {
        let p: Option<PendingPair> = self.load_json("pending-pair.json")?;
        Ok(p.filter(|p| p.expires_unix > now_unix() && p.failures < PAIRING_MAX_FAILURES))
    }

    pub fn end_pairing(&self) {
        let _ = fs::remove_file(self.path("pending-pair.json"));
    }

    /// Count a failed attempt; the code dies after PAIRING_MAX_FAILURES.
    pub fn pairing_failed(&self) -> Result<()> {
        if let Some(mut p) = self.load_json::<PendingPair>("pending-pair.json")? {
            p.failures += 1;
            if p.failures >= PAIRING_MAX_FAILURES {
                self.end_pairing();
            } else {
                self.save_json("pending-pair.json", &p)?;
            }
        }
        Ok(())
    }

    pub fn audit(&self, line: &str) {
        let r = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path("audit.log"))
            .and_then(|mut f| writeln!(f, "{} {line}", timestamp()));
        if let Err(e) = r {
            warn!("cannot write audit log: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors() {
        assert!(selector_matches("1050:0407", 0x1050, 0x0407));
        assert!(selector_matches("1050:*", 0x1050, 0x1234));
        assert!(selector_matches("*", 1, 2));
        assert!(selector_matches(" 1050:0407 ", 0x1050, 0x0407));
        assert!(!selector_matches("1050:0407", 0x1050, 0x0406));
        assert!(!selector_matches("1050", 0x1050, 0x0407));
        assert!(!selector_matches("zzzz:*", 0x1050, 0x0407));
    }

    #[test]
    fn pairing_lifecycle() {
        let dir = std::env::temp_dir().join(format!("usbwire-state-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let st = State::open(&dir).unwrap();
        assert!(st.pending_pairing().unwrap().is_none());
        let p = st.start_pairing("laptop", vec!["1050:*".into()]).unwrap();
        assert_eq!(st.pending_pairing().unwrap().unwrap().code, p.code);
        for _ in 0..PAIRING_MAX_FAILURES {
            st.pairing_failed().unwrap();
        }
        assert!(st.pending_pairing().unwrap().is_none(), "code must die after too many failures");

        st.add_client(Client {
            fingerprint: "ab".repeat(32),
            name: "laptop".into(),
            allow: vec!["*".into()],
            paired_at: timestamp(),
        })
        .unwrap();
        assert!(st.client(&"ab".repeat(32)).unwrap().is_some());
        assert_eq!(st.revoke("laptop").unwrap().len(), 1);
        assert!(st.clients().unwrap().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
