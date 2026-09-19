//! Host configuration: `~/.config/mypass/browser.json`. All fields are optional;
//! a missing file means all-defaults, so the
//! host runs even before `mypass install-browser` has written one.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// The vault file. A leading `~/` is expanded to the home directory.
    #[serde(default = "default_file")]
    pub file: String,
    /// Minutes to keep decrypted entries in memory; `0` re-prompts every time.
    #[serde(default = "default_cache_minutes")]
    pub cache_minutes: u64,
    /// Optional path to a debug log file. When set (or when `$MYPASS_BROWSER_LOG`
    /// is set, which wins), the host appends diagnostic lines describing its
    /// environment, the pinentry exchange and each request — never any secret.
    /// A leading `~/` is expanded. Absent by default, so logging is off.
    #[serde(default)]
    pub log_file: Option<String>,
}

fn default_file() -> String {
    "~/mypass.scrypt".to_string()
}

fn default_cache_minutes() -> u64 {
    10
}

impl Config {
    /// Load the config, or fall back to all-defaults when the file is absent.
    /// The path is `$MYPASS_BROWSER_CONFIG` when set (used by tests), otherwise
    /// `~/.config/mypass/browser.json`.
    pub fn load() -> anyhow::Result<Config> {
        let path = config_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // `{}` deserializes to all field defaults.
                Ok(serde_json::from_str("{}").expect("default config is valid"))
            }
            Err(e) => Err(anyhow::anyhow!(
                "cannot read config {}: {e}",
                path.display()
            )),
        }
    }

    /// The vault path with `~/` expanded.
    pub fn vault_file(&self) -> PathBuf {
        expand_tilde(&self.file)
    }

    /// The debug-log destination, if any: `$MYPASS_BROWSER_LOG` overrides the
    /// config's `log_file`. A `~/` prefix in either is expanded.
    pub fn log_file(&self) -> Option<PathBuf> {
        if let Some(env) =
            std::env::var_os("MYPASS_BROWSER_LOG").or_else(|| std::env::var_os("PW_BROWSER_LOG"))
        {
            if !env.is_empty() {
                return Some(expand_tilde(&env.to_string_lossy()));
            }
        }
        self.log_file.as_deref().map(expand_tilde)
    }
}

/// `~/.config/mypass`, where the host config lives.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mypass")
}

fn config_path() -> PathBuf {
    if let Some(path) =
        std::env::var_os("MYPASS_BROWSER_CONFIG").or_else(|| std::env::var_os("PW_BROWSER_CONFIG"))
    {
        return PathBuf::from(path);
    }
    config_dir().join("browser.json")
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}
