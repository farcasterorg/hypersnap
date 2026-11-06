use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Relay shared user messages between committed Hypersnap and Snapchain blocks")]
struct Cli {
    #[arg(long, default_value = "shuttle.toml")]
    config_path: PathBuf,
    /// Validate configuration without connecting to either network.
    #[arg(long)]
    check_config: bool,
}
#[tokio::main]
async fn main() -> Result<(), snapchain::shuttle::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Cli::parse();
    let config = snapchain::shuttle::Config::load(&args.config_path)?;
    if args.check_config {
        println!("Shuttle configuration is valid");
        return Ok(());
    }
    snapchain::shuttle::run(config).await
}
