//! A front end exposing only the deployment commands (`install`, `update`,
//! `uninstall`, `version`), for testing the installer and updater
//! independently of the full `cardinal` CLI. Not shipped.

use clap::Parser;

#[derive(Parser)]
#[command(name = "cardinal")]
struct Cli {
    #[command(subcommand)]
    cmd: cardinal_update::DeployCommand,
}

fn main() {
    if let Err(e) = cardinal_update::run(Cli::parse().cmd) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
