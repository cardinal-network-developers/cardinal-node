//! `config.toml`: the parts the installer and updater use.
//!
//! The file is shared with the rest of `cardinal`; only the `[update]`
//! table is read here and every other table is left alone.
//!
//! ```toml
//! [update]
//! channel = "stable"            # or "dev"
//! source = "https://example.org/cardinal/releases"   # URL or directory
//! auto_check = true
//! ```

use std::path::Path;

use anyhow::Context;

/// Release channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Signed releases from the configured source.
    Stable,
    /// Development builds from `scripts/dev-release.sh`.
    Dev,
}

/// Update settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateConfig {
    /// Release channel, if set. Unset means: follow the installed binary
    /// (`Dev` for development builds, else `Stable`).
    pub channel: Option<Channel>,
    /// Where releases come from, if configured.
    pub source: Option<String>,
    /// Whether the daemon should check for updates on its own (it only
    /// reports them; installing is always `cardinal update`).
    pub auto_check: bool,
}

impl UpdateConfig {
    /// Defaults.
    pub fn default_for_build() -> UpdateConfig {
        UpdateConfig {
            channel: None,
            source: None,
            auto_check: true,
        }
    }

    /// Reads the `[update]` table of `path`; a missing file gives the
    /// defaults.
    pub fn load(path: &Path) -> anyhow::Result<UpdateConfig> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default_for_build())
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// Parses config text.
    pub fn parse(text: &str) -> anyhow::Result<UpdateConfig> {
        let mut cfg = Self::default_for_build();
        let table: toml::Table = text.parse()?;
        let Some(update) = table.get("update") else {
            return Ok(cfg);
        };
        let update = update
            .as_table()
            .ok_or_else(|| anyhow::anyhow!("[update] must be a table"))?;
        if let Some(c) = update.get("channel") {
            cfg.channel = match c.as_str() {
                Some("stable") => Some(Channel::Stable),
                Some("dev") => Some(Channel::Dev),
                _ => anyhow::bail!("update.channel must be \"stable\" or \"dev\""),
            };
        }
        if let Some(s) = update.get("source") {
            let s = s
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("update.source must be a string"))?;
            if !s.trim().is_empty() {
                cfg.source = Some(s.trim().to_string());
            }
        }
        if let Some(a) = update.get("auto_check") {
            cfg.auto_check = a
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("update.auto_check must be true or false"))?;
        }
        Ok(cfg)
    }
}

/// The file `cardinal install` writes when there is none.
pub fn template() -> String {
    String::from(
        "# Cardinal configuration.\n\
         \n\
         [update]\n\
         # \"stable\" for releases from `source`; \"dev\" for builds made by\n\
         # scripts/dev-release.sh (default source: ~/.local/share/cardinal-dev-releases).\n\
         # Unset: \"dev\" when the installed binary is a development build.\n\
         # channel = \"stable\"\n\
         \n\
         # Where `cardinal update` looks for releases: an https:// URL or a local\n\
         # directory holding `manifest` and `manifest.sig`.\n\
         # source = \"https://example.org/cardinal/releases\"\n\
         \n\
         # Let the daemon check for (but never install) new releases.\n\
         auto_check = true\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_update_table_and_ignores_others() {
        let c = UpdateConfig::parse(
            "[daemon]\nlisten = [\"a\", \"b\"]\n[update]\nchannel = \"dev\"\nsource = \"/tmp/r\"\nauto_check = false\n",
        )
        .unwrap();
        assert_eq!(c.channel, Some(Channel::Dev));
        assert_eq!(c.source.as_deref(), Some("/tmp/r"));
        assert!(!c.auto_check);
        assert!(UpdateConfig::parse("[update]\nchannel = \"beta\"\n").is_err());
        assert_eq!(
            UpdateConfig::parse("").unwrap(),
            UpdateConfig::default_for_build()
        );
    }

    #[test]
    fn template_parses() {
        let c = UpdateConfig::parse(&template()).unwrap();
        assert_eq!(c, UpdateConfig::default_for_build());
    }
}
