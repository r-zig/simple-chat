use std::{error::Error, net::SocketAddr, sync::Arc};
mod actors;
mod messages;
mod transport;
use crate::actors::chat_actor::ChatActor;
use crate::messages::{ChatMessage, Join, Leave};
use crate::transport::TransportReceiver;
use crate::transport::{QuinnTransportReceiver, QuinnTransportSender};
use actix::{Actor, Addr};
use chat_contract::chat;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use quinn::{Endpoint, ServerConfig, VarInt};
use tokio::sync::Mutex;
use tracing::{debug, error, info, info_span};
use tracing_futures::Instrument;
use tracing_subscriber::fmt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

use anyhow::Result;
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
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "127.0.0.1:4433")]
    listen: SocketAddr,
    /// Client address to block
    #[clap(long = "block")]
    block: Option<SocketAddr>,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    connection_limit: Option<usize>,

    #[clap(long = "max-uni_streams")]
    max_concurrent_uni_streams: Option<u64>,

    #[clap(long = "max-bidi-streams")]
    max_concurrent_bidi_streams: Option<u64>,
}

pub async fn run(options: Opt) -> Result<()> {
    let (endpoint, _server_cert) = make_server_endpoint(&options).unwrap();
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
                    error!("error accepting stream: {reason}", reason = e.to_string());
                    return Err(e);
                }
                Ok(s) => {
                    debug!("Accepted a bidirectional stream");
                    s
                }
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

/// Returns default server configuration along with its certificate.
fn configure_server(
    option: &Opt,
) -> Result<(ServerConfig, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![cert_der.clone()], priv_key.into())?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    if let Some(max_concurrent_uni_streams) = option.max_concurrent_uni_streams {
        transport_config.max_concurrent_uni_streams(VarInt::from_u64(max_concurrent_uni_streams)?);
    }
    if let Some(max_concurrent_bidi_streams) = option.max_concurrent_bidi_streams {
        transport_config
            .max_concurrent_bidi_streams(VarInt::from_u64(max_concurrent_bidi_streams)?);
    }

    Ok((server_config, cert_der))
}

pub fn make_server_endpoint(
    options: &Opt,
) -> Result<(Endpoint, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let (server_config, server_cert) = configure_server(options)?;
    let endpoint = Endpoint::server(server_config, options.listen)?;
    Ok((endpoint, server_cert))
}
