use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use protobuf_stream::protobuf_stream::{ProtobufStream, ProtobufStreamError};
use quinn::{
    crypto::rustls::QuicClientConfig, rustls::pki_types::CertificateDer, ClientConfig, Endpoint,
    RecvStream, SendStream,
};
use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    sync::mpsc::Receiver,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use chat_contract::{
    builders::ClientMessageBuilder,
    chat::{client_message::Payload, ClientMessage, ServerMessage},
};

#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct Opt {
    /// Server address to connect to
    #[clap(long = "server-addr")]
    server_addr: SocketAddr,

    /// Server name for identification
    #[clap(long = "server-name")]
    server_name: String,

    /// Client name for identification
    #[clap(long = "name")]
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();
    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer());
    tracing::subscriber::set_global_default(subscriber).unwrap();
    println!("Starting {}", app_name);
    println!("Created by: {}", env!("CARGO_PKG_AUTHORS"));

    let options = Opt::parse();

    // Create a QUIC client endpoint
    let endpoint = create_client_endpoint()?;
    info!("Connecting to server at {}", options.server_addr);
    let connection = endpoint
        .connect(options.server_addr, &options.server_name)
        .unwrap()
        .await?;
    println!("Connected to server at {}", options.server_addr);

    let (send_stream, mut recv_stream) = connection.open_bi().await.unwrap();
    let send_stream = Arc::new(tokio::sync::Mutex::new(send_stream));

    let send_stream_clone = send_stream.clone();
    // Send a join message
    send_join(&options.name, send_stream.clone()).await?;

    // Create a channel for sending messages from the input handler to the sender
    let (message_tx, message_rx) = tokio::sync::mpsc::channel::<ClientMessage>(100);

    // Spawn a task to handle user input
    let user_name = options.name.clone();

    // Wait for all tasks to complete or Ctrl+C
    tokio::select! {
        _ = handle_user_input(&user_name, message_tx) => {
            debug!("Input task completed");
        }
        _ = send_message(send_stream,message_rx) => {
            debug!("Send task completed");
        }
        _ = read_logic(&mut recv_stream) => {
            debug!("Read task completed");
        }
        _ = tokio::signal::ctrl_c() => {
            debug!("Ctrl+C received, shutting down...");
            send_leave(&options.name, send_stream_clone).await?;
            // let the server receive the leave message
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn create_client_endpoint() -> Result<Endpoint> {
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;

    endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth(),
    )?)));
    Ok(endpoint)
}

async fn send_message(
    send_stream: Arc<Mutex<SendStream>>,
    mut message_rx: Receiver<ClientMessage>,
) -> Result<()> {
    let mut should_shutdown = false;
    while let Some(message) = message_rx.recv().await {
        if let Some(payload) = message.payload.clone() {
            match payload {
                Payload::Leave(_) => {
                    debug!("Leave message sent, will start shutdown");
                    should_shutdown = true;
                }
                _ => {
                    debug!("Other message sent");
                }
            }
        }

        match Vec::<u8>::try_from(message) {
            Ok(buf) => {
                if let Err(e) = send_stream.lock().await.write_all(&buf).await {
                    error!("Failed to send message: {:?}", e);
                } else {
                    debug!("Message sent successfully");
                }
            }
            Err(e) => {
                error!("Failed to encode message: {:?}", e);
            }
        }
        if should_shutdown {
            // let the server receive the leave message
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            debug!("Leave message sent, shutting down...");
            break;
        }
    }
    Ok(())
}

async fn read_logic(recv_stream: &mut RecvStream) -> Result<()> {
    println!("Waiting for messages...");
    // Read the server's response
    let reader = BufReader::new(recv_stream);
    let mut stream = ProtobufStream::<_, ServerMessage>::new(reader);

    // Loop over the stream to handle multiple messages
    loop {
        let response = stream.next().await;
        match response {
            Some(Ok(msg)) => {
                if let Some(e) = msg.error {
                    println!("Server error occurred: {:?}", e);
                } else {
                    match msg.chat {
                        Some(message) => {
                            println!(
                                "Received message from: {}",
                                message
                                    .header
                                    .map(|h| h.username)
                                    .unwrap_or("Unknown".to_string())
                            );
                            println!("{}", message.content);
                        }
                        None => {
                            println!("Received empty message");
                        }
                    }
                }
            }
            Some(Err(ProtobufStreamError::Recoverable { code, source })) => {
                // Handle the specific "Pending" error
                debug!(
                    "Stream operation is pending: {:?}, error: {:?}, continue to next item",
                    code, source
                );
                continue;
            }
            Some(Err(ProtobufStreamError::NonRecoverable { code, source })) => {
                error!(
                    "Stream operation failed. code {:?}, error: {:?}",
                    code, source
                );
                println!("Non recoverable error occurred {:?}", code);
                break;
            }
            Some(Err(ProtobufStreamError::Other {
                message,
                code,
                source,
            })) => {
                error!(
                    "Stream operation failed. code: {:?}, message: {}, error: {:?}",
                    code, message, source
                );
                println!("Other Error occurred {:?}", code);
                break;
            }
            None => {
                // Stream ended
                debug!("Stream ended");
                break;
            }
        }
    }
    debug!("Read logic task completed");
    Ok(())
}

async fn handle_user_input(user: &str, tx: tokio::sync::mpsc::Sender<ClientMessage>) {
    let mut reader = BufReader::new(io::stdin()).lines();

    println!("Enter commands (e.g., 'send <MSG>' or 'leave'):");

    loop {
        // Read user input
        let line = reader.next_line().await;
        match line {
            Ok(Some(line)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Split the input into command and the rest of the string
                let (command, rest) = match trimmed.split_once(' ') {
                    Some((cmd, rest)) => (cmd, rest),
                    None => (trimmed, ""), // If there's no space, treat the whole input as the command
                };

                let message = match command {
                    "send" => {
                        let content = rest.to_string();
                        ClientMessageBuilder::new()
                            .chat(user, content, None)
                            .build()
                    }
                    "leave" => ClientMessageBuilder::new().leave(user, None).build(),
                    _ => {
                        println!("Unknown command: {}", command);
                        continue;
                    }
                };

                if let Ok(msg) = message {
                    if tx.send(msg).await.is_err() {
                        error!("Failed to send message to sender task");
                        break;
                    }
                }

                if command == "leave" {
                    println!("Leaving the connection...");
                } else {
                    println!("Enter commands (e.g., 'send <MSG>' or 'leave'):");
                }
            }
            Ok(None) => {
                // EOF reached
                break;
            }
            Err(e) => {
                error!("Error reading input: {:?}", e);
                break;
            }
        }
    }
    debug!("User input task completed");
}

async fn send_join(name: &str, send_stream: Arc<Mutex<SendStream>>) -> Result<()> {
    let client_message = ClientMessageBuilder::new()
        .join(name, None)
        .build()
        .unwrap();

    // Send the `Join` message - encode it to bytes with length prefix
    let buf: Vec<u8> = client_message.try_into().unwrap();

    send_stream.lock().await.write_all(&buf).await?;

    println!("Sent join message as {}", name);
    Ok(())
}

async fn send_leave(name: &str, send_stream: Arc<Mutex<SendStream>>) -> Result<()> {
    let client_message = ClientMessageBuilder::new()
        .leave(name, None)
        .build()
        .unwrap();

    // Send the `Join` message - encode it to bytes with length prefix
    let buf: Vec<u8> = client_message.try_into().unwrap();

    send_stream.lock().await.write_all(&buf).await?;
    println!("User {} send leave message", name);
    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
