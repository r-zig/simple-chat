mod actors;
mod messages;
mod transport;
use crate::actors::chat_actor::ChatActor;
use crate::messages::{ChatMessage, Join, Leave};
use crate::transport::TransportReceiver;
use crate::transport::{QuinnTransportReceiver, QuinnTransportSender};
use actix::{Actor, Addr};
use chat_contract::chat;
use quinn_proto::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use quinn::ServerConfig;
use std::sync::Arc;
use std::{fs, io, net::SocketAddr, path::PathBuf};
use tokio::sync::Mutex;
use tracing::{error, info, info_span};
use tracing_futures::Instrument;
use tracing_subscriber::fmt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[actix::main]
async fn main() -> Result<()> {
    let app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();
    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer());
    tracing::subscriber::set_global_default(subscriber).unwrap();
    println!("Starting {}", app_name);
    println!("Created by: {}", env!("CARGO_PKG_AUTHORS"));

    let options = Opt::parse();
    run(options)
        .await
        .inspect_err(|e| {
            error!("Error: {reason}", reason = e.to_string());
        })
        .unwrap_or_else(|_| {
            println!("Server stopped");
        });
    Ok(())
}

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct Opt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    keylog: bool,

    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,
    /// Client address to block
    #[clap(long = "block")]
    block: Option<SocketAddr>,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    connection_limit: Option<usize>,
}

pub async fn run(options: Opt) -> Result<()> {
    let mut server_config = build_server_config(&options)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    info!("listening on {}", endpoint.local_addr()?);
    let chat_actor = ChatActor::<QuinnTransportSender>::new().start();

    while let Some(conn) = endpoint.accept().await {
        if options
            .connection_limit
            .is_some_and(|n| endpoint.open_connections() >= n)
        {
            info!("refusing due to open connection limit");
            conn.refuse();
        } else if Some(conn.remote_address()) == options.block {
            info!("refusing blocked client IP address");
            conn.refuse();
        } else if options.stateless_retry && !conn.remote_address_validated() {
            info!("requiring connection to validate its address");
            conn.retry().unwrap();
        } else {
            info!("accepting connection");
            let fut = handle_connection(conn, chat_actor.clone());
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    }

    Ok(())
}

async fn handle_connection(
    conn: quinn::Incoming,
    chat_actor: Addr<ChatActor<QuinnTransportSender>>,
) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            // Create the TransportSender and TransportReceiver
            let sender = Arc::new(Mutex::new(QuinnTransportSender::new(stream.0)));
            let mut receiver = QuinnTransportReceiver::new(
                stream.1,
                create_message_handler(chat_actor.clone(), sender.clone()), // Use the message handler
            );
            receiver.start().await.unwrap();
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

pub fn create_message_handler(
    chat_actor: Addr<ChatActor<QuinnTransportSender>>,
    sender: Arc<Mutex<QuinnTransportSender>>,
) -> Box<dyn Fn(chat::ClientMessage) + Send + Sync> {
    Box::new(move |client_message: chat::ClientMessage| {
        if let Some(payload) = client_message.payload {
            match payload {
                chat::client_message::Payload::Join(join) => {
                    chat_actor.do_send(Join::new(join, sender.clone()));
                }
                chat::client_message::Payload::Leave(leave) => {
                    chat_actor.do_send(Leave::new(leave));
                }
                chat::client_message::Payload::Chat(chat_message) => {
                    chat_actor.do_send(ChatMessage::new(chat_message));
                }
            }
        } else {
            error!("ClientMessage payload is empty");
        }
    })
}

fn build_server_config(options: &Opt) -> Result<ServerConfig, anyhow::Error> {
    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = if key_path.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .context("malformed PKCS #1 private key")?
                .ok_or_else(|| anyhow::Error::msg("no private keys found"))?
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
            vec![CertificateDer::from(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .collect::<Result<_, _>>()
                .context("invalid PEM-encoded certificate")?
        };

        (cert_chain, key)
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok((cert, key)) => (
                CertificateDer::from(cert),
                PrivateKeyDer::try_from(key).map_err(anyhow::Error::msg)?,
            ),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
                let cert = cert.cert.into();
                fs::create_dir_all(path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, key.secret_pkcs8_der())
                    .context("failed to write private key")?;
                (cert, key.into())
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };

        (vec![cert], key)
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    if options.keylog {
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let server_config: quinn::ServerConfig =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    Ok(server_config)
}
