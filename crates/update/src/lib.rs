//! Installing, updating, and uninstalling `cardinal` for one user.
//!
//! The CLI embeds [`DeployCommand`] and hands it to [`run`]. Everything
//! about where files go, how releases are verified, and how the service is
//! restarted lives here.

use clap::Subcommand;

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
    /// Stop the service and remove the binary and unit.
    Uninstall {
        /// Also delete all local data and keys.
        #[arg(long)]
        purge: bool,
    },
    /// Print version and build information.
    Version,
}

/// Run a deployment subcommand.
pub fn run(cmd: DeployCommand) -> anyhow::Result<()> {
    match cmd {
        DeployCommand::Version => {
            println!("cardinal {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => anyhow::bail!("not implemented yet: {other:?}"),
    }
}
