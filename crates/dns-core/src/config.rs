//! On-disk configuration: DoH providers, routing policy, and per-game profiles.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::policy::Policy;
use crate::provider::{default_providers, Provider};

/// Optional per-app override: domains forced over DoH while the profile is
/// active, plus a launch command. Not needed for ordinary use — the default
/// policy already sends every public name over DoH.
///
/// Domain lists must come from observed traffic, never guesses: a wrong entry
/// silently sends traffic somewhere it should not go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppProfile {
    /// Stable identifier used in the UI and IPC.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Domains and suffixes forced over DoH while this profile is active.
    /// A leading `*.` matches subdomains only.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Command used to launch the app.
    #[serde(default)]
    pub launch_command: Option<String>,
    /// Arguments passed to `launch_command`.
    #[serde(default)]
    pub launch_args: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// An app the GUI can launch inside the per-app tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelApp {
    /// Display name, also the launch identifier.
    pub name: String,
    /// Program to run, e.g. `brave`.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Process name used to detect an already-running, untunnelled instance.
    /// Defaults to the command's file name.
    #[serde(default)]
    pub process: Option<String>,
}

impl TunnelApp {
    pub fn new(name: &str, command: &str) -> Self {
        Self { name: name.into(), command: command.into(), args: Vec::new(), process: None }
    }

    pub fn process_name(&self) -> &str {
        self.process.as_deref().unwrap_or_else(|| {
            self.command.rsplit('/').next().unwrap_or(&self.command)
        })
    }
}

fn default_tunnel_apps() -> Vec<TunnelApp> {
    vec![TunnelApp::new("Brave", "brave"), TunnelApp::new("Steam", "steam")]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address the proxy binds. A dedicated loopback alias avoids colliding
    /// with anything already on 127.0.0.1:53.
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_providers")]
    pub providers: Vec<Provider>,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub profiles: Vec<AppProfile>,
    #[serde(default = "default_tunnel_apps")]
    pub tunnel_apps: Vec<TunnelApp>,
}

fn default_listen() -> String {
    "127.0.0.53:53".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            providers: default_providers(),
            policy: Policy::default(),
            profiles: Vec::new(),
            tunnel_apps: default_tunnel_apps(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid TOML: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("could not serialise config: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("could not determine a config directory")]
    NoConfigDir,
}

impl Config {
    /// `$XDG_CONFIG_HOME/detour/config.toml`, falling back to `~/.config`.
    ///
    /// Moves a directory left by the app's earlier name (`wuwa-dns`) into place
    /// the first time, so an existing config and tunnel keys carry over.
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .ok_or(ConfigError::NoConfigDir)?;
        let dir = base.join("detour");
        let legacy = base.join("wuwa-dns");
        if !dir.exists() && legacy.is_dir() {
            let _ = std::fs::rename(&legacy, &dir);
        }
        Ok(dir.join("config.toml"))
    }

    /// Load from disk, or return defaults if the file does not exist yet.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.display().to_string(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })
    }

    /// Reject settings that would leave DNS broken. Checked before saving,
    /// since a bad provider list only fails later, when protection starts.
    pub fn validate(&self) -> Result<(), String> {
        if self.providers.is_empty() {
            return Err("at least one DoH provider is required".into());
        }
        for p in &self.providers {
            if p.name.trim().is_empty() {
                return Err("every provider needs a name".into());
            }
            if p.host().is_none() {
                return Err(format!("{}: the URL must start with https://", p.name));
            }
            if p.bootstrap.is_empty() {
                return Err(format!(
                    "{}: needs at least one bootstrap IP, so resolving the provider \
                     never depends on DNS that is itself being redirected here",
                    p.name
                ));
            }
        }
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| format!("listen address {:?} is not IP:port", self.listen))?;
        Ok(())
    }

    pub fn tunnel_app(&self, name: &str) -> Option<&TunnelApp> {
        self.tunnel_apps.iter().find(|a| a.name == name)
    }

    pub fn profile(&self, id: &str) -> Option<&AppProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Policy with the named profile's domains forced onto DoH.
    pub fn policy_for(&self, profile_id: Option<&str>) -> Policy {
        let mut policy = self.policy.clone();
        if let Some(profile) = profile_id.and_then(|id| self.profile(id)) {
            // Add to the user's own always-DoH list, never replace it.
            let merged: Vec<String> = policy
                .force_doh
                .iter()
                .cloned()
                .chain(profile.domains.iter().cloned())
                .collect();
            policy.set_force_doh(merged);
        }
        policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Route;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    #[test]
    fn default_config_round_trips_through_toml() {
        let config = Config::default();
        let text = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.listen, "127.0.0.53:53");
        assert_eq!(parsed.providers.len(), 3);
        assert!(parsed.profiles.is_empty(), "no app-specific profile ships by default");
        assert_eq!(parsed.tunnel_apps, default_tunnel_apps());
    }

    #[test]
    fn older_config_without_tunnel_apps_gets_defaults() {
        let parsed: Config = toml::from_str("listen = \"127.0.0.53:53\"\n").unwrap();
        assert_eq!(parsed.tunnel_apps.len(), 2);
    }

    #[test]
    fn process_name_defaults_to_command_basename() {
        assert_eq!(TunnelApp::new("X", "/opt/foo/bin/foo").process_name(), "foo");
        let mut a = TunnelApp::new("Y", "flatpak");
        a.process = Some("real".into());
        assert_eq!(a.process_name(), "real");
    }

    #[test]
    fn missing_file_yields_defaults() {
        let config = Config::load(Path::new("/nonexistent/detour/config.toml")).unwrap();
        assert!(config.profiles.is_empty());
        assert_eq!(config.tunnel_apps.len(), 2);
    }

    #[test]
    fn invalid_toml_is_an_error_not_a_silent_default() {
        let dir = std::env::temp_dir().join("detour-test-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "this is not [ valid toml").unwrap();
        assert!(matches!(Config::load(&path), Err(ConfigError::Parse { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_preserves_profiles() {
        let dir = std::env::temp_dir().join("detour-test-roundtrip");
        let path = dir.join("config.toml");
        let mut config = Config::default();
        config.profiles.push(AppProfile {
            id: "other-game".into(),
            name: "Other Game".into(),
            domains: vec!["cdn.example.com".into()],
            launch_command: Some("wine".into()),
            launch_args: vec!["game.exe".into()],
            notes: None,
        });
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profile("other-game").unwrap().domains, vec!["cdn.example.com"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn profile_domains_are_forced_onto_doh() {
        let mut config = Config::default();
        config.policy.default_doh = false;
        config.profiles.push(AppProfile {
            id: "game".into(),
            name: "Game".into(),
            domains: vec!["*.example.com".into()],
            launch_command: None,
            launch_args: vec![],
            notes: None,
        });

        let policy = config.policy_for(Some("game"));
        assert_eq!(
            policy.route(&Name::from_str("cdn.example.com.").unwrap()),
            Route::Doh
        );
        assert_eq!(
            policy.route(&Name::from_str("unrelated.test.").unwrap()),
            Route::SystemUpstream
        );
    }

    #[test]
    fn profile_domains_add_to_user_force_doh_list() {
        let mut config = Config::default();
        config.policy.force_doh = vec!["mine.example".into()];
        config.profiles.push(AppProfile {
            id: "p".into(),
            name: "P".into(),
            domains: vec!["game.example".into()],
            launch_command: None,
            launch_args: vec![],
            notes: None,
        });
        let policy = config.policy_for(Some("p"));
        assert!(policy.force_doh.contains(&"mine.example".to_string()));
        assert!(policy.force_doh.contains(&"game.example".to_string()));
    }

    #[test]
    fn default_config_is_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn validation_rejects_settings_that_break_dns() {
        let mut c = Config::default();
        c.providers.clear();
        assert!(c.validate().is_err(), "no providers");

        let mut c = Config::default();
        c.providers[0].url = "http://insecure.example/dns-query".into();
        assert!(c.validate().is_err(), "non-https");

        let mut c = Config::default();
        c.providers[0].bootstrap.clear();
        assert!(c.validate().is_err(), "no bootstrap");

        let mut c = Config::default();
        c.listen = "nonsense".into();
        assert!(c.validate().is_err(), "bad listen");
    }

    #[test]
    fn presets_are_all_valid_and_exclude_family_filters() {
        let c = Config { providers: crate::provider::presets(), ..Config::default() };
        assert!(c.validate().is_ok());
        for p in crate::provider::presets() {
            assert!(!p.url.contains("family"), "{} enforces content filtering", p.name);
        }
    }

    #[test]
    fn unknown_profile_leaves_policy_untouched() {
        let config = Config::default();
        let policy = config.policy_for(Some("does-not-exist"));
        assert!(policy.force_doh.is_empty());
    }
}
