//! The service alone, for a client to start: on Windows and Android there is
//! no command line for a person to use, and nothing else of `cardinal`
//! applies.
//!
//! `cardinald [--listen IP:PORT] [--name NAME] [--no-discovery]`

use cardinald::paths::Paths;
use cardinald::Overrides;

fn main() -> anyhow::Result<()> {
    let mut o = Overrides {
        no_mount: !cfg!(feature = "mount"),
        ..Overrides::default()
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => o.listen = args.next(),
            "--name" => o.name = args.next(),
            "--no-discovery" => o.no_discovery = true,
            other => anyhow::bail!("{other} is not an option of cardinald"),
        }
    }
    cardinald::init_logging();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(cardinald::run(Paths::from_env(), o))
}
