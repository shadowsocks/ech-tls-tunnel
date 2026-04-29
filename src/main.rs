use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ech_tls_tunnel::config::Config;
use ech_tls_tunnel::ech::{encode_config_list_b64, EchServerKey};
use ech_tls_tunnel::sip003::SipEnv;
use ech_tls_tunnel::{client, server};
use tracing::error;

#[derive(Parser)]
#[command(
    name = "ech-tls-tunnel",
    about = "SIP003 plugin: shadowsocks over WebSocket / TLS / ECH"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an HPKE X25519 keypair, write the private key to
    /// `<out>/ech.key`, write the binary ECHConfigList to
    /// `<out>/ech.config_list`, and print the base64 ECHConfigList
    /// (ready to paste into the client's `ech_config=` plugin option).
    EchGenKeys {
        /// Outer (cleartext) SNI to advertise to public observers.
        #[arg(long)]
        public_name: String,
        /// Output directory.
        #[arg(long, default_value = "/var/lib/ech-tls-tunnel/ech")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        return run_subcommand(cmd);
    }

    // No subcommand → SIP003 plugin mode.
    init_tracing();
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

fn run_subcommand(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::EchGenKeys { public_name, out } => {
            std::fs::create_dir_all(&out)?;
            let key = EchServerKey::generate(&public_name)?;
            let key_path = out.join("ech.key");
            key.write_to(&key_path)?;
            let list = key.marshal_config_list()?;
            let list_path = out.join("ech.config_list");
            std::fs::write(&list_path, &list)?;
            let b64 = encode_config_list_b64(&list);
            println!("Wrote {}", key_path.display());
            println!("Wrote {}", list_path.display());
            println!();
            println!("ECHConfigList (base64):");
            println!("{b64}");
            println!();
            println!("Server plugin options:");
            println!(
                "    ech_public_name={public_name};ech_key={}",
                key_path.display()
            );
            println!("Client plugin options:");
            println!("    ech_config={b64}");
            Ok(())
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}
