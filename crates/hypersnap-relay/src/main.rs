use clap::Parser;
use hypersnap_relay::metrics::CountingMetrics;
use hypersnap_relay::{RelayBuilder, RelayConfig, Shutdown};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Hypersnap <-> snapchain relay worker (FIP Appendix A).
#[derive(Parser, Debug)]
#[command(name = "hypersnap-relay", version)]
struct Cli {
    /// TOML config file (see relay.example.toml). Without it, only defaults
    /// and HYPERSNAP_RELAY_* variables apply.
    #[arg(long, env = "HYPERSNAP_RELAY_CONFIG")]
    config: Option<PathBuf>,

    /// `text` or `json`.
    #[arg(long, env = "HYPERSNAP_RELAY_LOG_FORMAT", default_value = "text")]
    log_format: String,
}

fn init_logging(format: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if format == "json" {
        builder.json().init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(&cli.log_format);
    // tonic's TLS stack uses rustls with ring.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = match RelayConfig::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "invalid configuration");
            return ExitCode::from(2);
        }
    };
    info!(
        network = config.network.as_str(),
        inbound = config.inbound_enabled,
        outbound = config.outbound_enabled,
        snapchain = ?config.snapchain_endpoints,
        hypersnap = ?config.hypersnap_endpoints,
        "hypersnap-relay starting"
    );

    let metrics = Arc::new(CountingMetrics::new());
    if config.metrics_log_interval_secs > 0 {
        let m = metrics.clone();
        let every = Duration::from_secs(config.metrics_log_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                for line in m.summary() {
                    info!(target: "relay_metrics", "{line}");
                }
            }
        });
    }

    let (trigger, shutdown) = Shutdown::new();
    tokio::spawn(async move {
        wait_for_signal().await;
        info!("shutdown requested");
        trigger.trigger();
    });

    match RelayBuilder::new(config)
        .metrics(metrics)
        .run(shutdown)
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "relay stopped with an error");
            ExitCode::FAILURE
        }
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
