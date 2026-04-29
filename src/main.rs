use anyhow::Result;
use ech_tls_tunnel::config::Config;
use ech_tls_tunnel::sip003::SipEnv;
use ech_tls_tunnel::{client, server};
use tracing::error;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let sip = SipEnv::from_env()?;
    let mode = sip.options.mode()?;
    let cfg = Config::from_options(&sip.options)?;
    let (listen, upstream) = sip.endpoints(mode);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let result = match cfg {
            Config::Server(s) => server::run(&listen, &upstream, s).await,
            Config::Client(c) => client::run(&listen, &upstream, c).await,
        };
        if let Err(e) = &result {
            error!("plugin exited: {e:#}");
        }
        result
    })
}
