//! Standalone committed-block shuttle. Each direction publishes signed user
//! messages to the other network's mempool; consensus/system messages stay local.
pub mod config;
mod publisher;
mod relay;
mod state;

pub use config::Config;
pub use relay::run;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
