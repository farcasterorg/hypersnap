//! Ogre: rolls a build onto a seeded devnet the way a release reaches mainnet,
//! and checks the network keeps working. See docs/ogre.md.

mod checks;
mod convert;
mod net;
mod run;
mod seed;

use clap::{Parser, Subcommand};
use convert::Error;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Export real accounts from a mainnet node into a seed file
    Seed(seed::Args),
    /// Build the seeded chain on the base release
    Chain(run::ChainArgs),
    /// Roll the release under test onto the seeded chain and check the network
    Run(run::RunArgs),
}

fn with_auth<T>(msg: T, auth: &str) -> tonic::Request<T> {
    use base64::Engine;
    let mut req = tonic::Request::new(msg);
    let value = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(auth)
    );
    req.metadata_mut()
        .insert("authorization", value.parse().unwrap());
    req
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    match Cli::parse().command {
        Command::Seed(args) => seed::run(args).await,
        Command::Chain(args) => run::chain(args).await,
        Command::Run(args) => {
            if !run::run(args).await? {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
