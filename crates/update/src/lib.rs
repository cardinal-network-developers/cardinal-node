//! Installing, updating, and uninstalling `cardinal` for one user.
//!
//! The CLI embeds [`DeployCommand`] and hands it to [`run`]. Everything
//! about where files go, how releases are verified, and how the service is
//! restarted lives here.
//!
//! Layout (all per user, no root; XDG variables respected):
//!
//! - binary: `~/.local/bin/cardinal` (previous one: `cardinal.previous`)
//! - unit: `~/.config/systemd/user/cardinal.service`
//! - data: `~/.local/share/cardinal`
//! - config: `~/.config/cardinal/config.toml`

use std::time::Duration;

use clap::Subcommand;

pub mod build_info;
pub mod config;
pub mod fsutil;
pub mod manifest;
pub mod ops;
pub mod paths;
pub mod source;
pub mod system;
pub mod version;

#[cfg(test)]
mod tests;

pub use build_info::VERSION;
pub use paths::Paths;

/// Subcommands the `cardinal` CLI exposes for deployment.
#[derive(Debug, Subcommand)]
pub enum DeployCommand {
    /// Install this binary for the current user and start the service.
    Install {
        /// Replace an existing installation without asking.
        #[arg(long)]
        force: bool,
    },
    /// Fetch, verify, and install the latest release.
    Update {
        /// Release source: a URL or a local directory. Defaults to the
        /// configured channel.
        #[arg(long)]
        from: Option<String>,
        /// Only report whether an update is available.
        #[arg(long)]
        check: bool,
    },
    /// Stop the service and remove the binary and unit. Without an option
    /// this says what stays, and asks first.
    Uninstall {
        /// Also delete all local data and keys.
        #[arg(long, conflicts_with = "keep_data")]
        purge: bool,
        /// Keep local data and keys, without asking.
        #[arg(long)]
        keep_data: bool,
    },
    /// Print version and build information.
    Version,
}

/// Run a deployment subcommand.
pub fn run(cmd: DeployCommand) -> anyhow::Result<()> {
    if let DeployCommand::Version = cmd {
        print!("{}", build_info::report());
        return Ok(());
    }
    let ctx = system_ctx()?;
    match cmd {
        DeployCommand::Install { force } => {
            let exe = std::env::current_exe()?;
            ops::install(&ctx, &exe, force)
        }
        DeployCommand::Update { from, check } => {
            ops::update(&ctx, from.as_deref(), check).map(|_| ())
        }
        DeployCommand::Uninstall { purge, keep_data } => ops::uninstall(
            &ctx,
            match (purge, keep_data) {
                (true, _) => ops::Data::Purge,
                (_, true) => ops::Data::Keep,
                _ => ops::Data::Ask,
            },
        ),
        DeployCommand::Version => unreachable!(),
    }
}

/// The context for the real user session.
///
/// Environment knobs: `CARDINAL_ALLOW_DOWNGRADE=1` permits installing an
/// older release; `CARDINAL_HEALTH_TIMEOUT` (seconds, default 20) bounds the
/// post-update service health check.
pub fn system_ctx() -> anyhow::Result<system::Ctx<'static>> {
    let health = std::env::var("CARDINAL_HEALTH_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20);
    Ok(system::Ctx {
        paths: Paths::from_env()?,
        runner: &system::SystemRunner,
        prompt: &system::TtyPrompt,
        release_key: build_info::RELEASE_PUBLIC_KEY,
        target: build_info::TARGET.to_string(),
        health_timeout: Duration::from_secs(health),
        health_poll: Duration::from_secs(1),
        allow_downgrade: std::env::var("CARDINAL_ALLOW_DOWNGRADE").is_ok_and(|v| v == "1"),
    })
}

/// For the daemon's periodic check: the newer release available from the
/// configured source, if any. Never installs anything. Callers should
/// honour [`config::UpdateConfig::auto_check`].
pub fn check_for_update() -> anyhow::Result<Option<String>> {
    let ctx = system_ctx()?;
    let installed = VERSION;
    let source = ops::resolve_source(&ctx, None, installed)?;
    let m = ops::fetch_manifest(&ctx, &source)?;
    if m.artifact_for(&ctx.target).is_none() {
        return Ok(None);
    }
    let newer = version::Version::parse(&m.version)? > version::Version::parse(installed)?;
    Ok(newer.then_some(m.version))
}
