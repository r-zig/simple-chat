use chat_contract::{
    builders::ClientMessageBuilder,
    chat::{ErrorCode, MessageType, ServerMessage},
};
use futures::StreamExt;
use protobuf_stream::protobuf_stream::{ProtobufStream, ProtobufStreamError};
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
use rustls_pki_types::CertificateDer;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::UNIX_EPOCH,
};
use std::{sync::Arc, time::SystemTime};
use tokio::io::BufReader;

const DEFAULT_SERVER_ADDRESS: &str = "127.0.0.1:4433";

async fn connect_to_server() -> Result<(quinn::Connection, Endpoint), Box<dyn Error>> {
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;

    endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth(),
    )?)));

    // Connect to the server
    let connection = endpoint
        .connect(DEFAULT_SERVER_ADDRESS.parse().unwrap(), "localhost")
        .unwrap()
        .await?;
    Ok((connection, endpoint))
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

#[tokio::test]
async fn test_server_accepts_connection() {
    let (connection, endpoint) = connect_to_server()
        .await
        .expect("Failed to connect to server");
    let _ = connection.open_bi().await.unwrap();
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn test_server_accepts_join() {
    let (connection, endpoint) = connect_to_server()
        .await
        .expect("Failed to connect to server");
    let (mut send_stream, recv_stream) = connection.open_bi().await.unwrap();

    let client_message = ClientMessageBuilder::new()
        .join("r-zig", None)
        .build()
        .unwrap();

    // Send the `Join` message - encode it to bytes with length prefix
    let buf: Vec<u8> = client_message.try_into().unwrap();
    for _ in 0..2 {
        match send_stream.write_all(&buf).await {
            Ok(_) => println!("Message sent successfully"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
    send_stream.finish().unwrap();

    // Read the server's response
    let reader = BufReader::new(recv_stream);
    let mut stream = ProtobufStream::<_, ServerMessage>::new(reader);

    // loop over the stream to handle multiple messages
    while let Some(response) = stream.next().await {
        match response {
            Ok(msg) => {
                let error = msg.error.unwrap();
                assert_eq!(error.r#type, MessageType::Join as i32);
                assert_eq!(error.code, ErrorCode::UsernameAlreadyTaken as i32);
                break;
            }
            Err(ProtobufStreamError::Recoverable { code, source }) => {
                // Handle the specific "Pending" error
                println!(
                    "Stream operation is pending: {:?}, error: {:?}, continue to next item",
                    code, source
                );
                continue;
            }
            Err(ProtobufStreamError::NonRecoverable { code, source }) => {
                panic!("Stream operation failed: {:?}, error: {:?}", code, source);
            }
            Err(ProtobufStreamError::Other {
                code,
                message,
                source,
            }) => {
                panic!(
                    "Stream operation failed with message: {:?}, code: {:?}, error: {:?}",
                    message, code, source
                );
            }
        }
    }
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn test_join_broadcast() {
    // Connect the first client
    let (connection1, endpoint1) = connect_to_server()
        .await
        .expect("Failed to connect to server");
    let (mut send_stream1, recv_stream1) = connection1.open_bi().await.unwrap();

    // Connect the second client
    let (connection2, endpoint2) = connect_to_server()
        .await
        .expect("Failed to connect to server");
    let (mut send_stream2, recv_stream2) = connection2.open_bi().await.unwrap();

    // Prepare receiving streams for both clients
    let reader1 = BufReader::new(recv_stream1);
    let mut stream1 = ProtobufStream::<_, ServerMessage>::new(reader1);

    let reader2 = BufReader::new(recv_stream2);
    let mut stream2 = ProtobufStream::<_, ServerMessage>::new(reader2);

    // Generate unique usernames using the current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();
    let username1 = format!("client1_{}", timestamp);
    let username2 = format!("client2_{}", timestamp);

    // First client sends a "Join" message
    let client_message1 = ClientMessageBuilder::new()
        .join(username1.clone(), None)
        .build()
        .unwrap();
    let buf1: Vec<u8> = client_message1.try_into().unwrap();
    send_stream1.write_all(&buf1).await.unwrap();
    send_stream1.finish().unwrap();

    // Second client sends a "Join" message
    let client_message2 = ClientMessageBuilder::new()
        .join(username2, None)
        .build()
        .unwrap();
    let buf2: Vec<u8> = client_message2.try_into().unwrap();
    send_stream2.write_all(&buf2).await.unwrap();
    send_stream2.finish().unwrap();

    // First client should not receive the broadcast
    tokio::select! {
        msg = stream1.next() => {
            match msg {
                Some(Ok(response)) => {
                    if let Some(chat) = response.chat {
                        assert_ne!(chat.content, format!("User {} has joined the room", username1));
                    }
                }
                Some(Err(e)) => {
                    println!("First client received an error: {:?}", e);
                    panic!("Unexpected error for first client");
                }
                None => {
                    println!("First client stream ended unexpectedly");
                    panic!("First client stream ended unexpectedly");
                }
            }
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
            // Timeout, as expected
            println!("First client did not receive any broadcast (as expected)");
        }
    }

    // Second client should receive the broadcast
    tokio::select! {
        msg = stream2.next() => {
            match msg {
                Some(Ok(response)) => {
                    if let Some(chat) = response.chat {
                        assert_eq!(
                            chat.content,
                            format!("User {} has joined the room", username1),
                            "Second client received an unexpected broadcast message"
                        );
                        println!("Second client received the expected broadcast: {:?}", chat.content);
                    } else {
                        panic!("Second client received a message without chat content");
                    }
                }
                Some(Err(e)) => {
                    println!("Second client received an error: {:?}", e);
                    panic!("Unexpected error for second client");
                }
                None => {
                    println!("Second client stream ended unexpectedly");
                    panic!("Second client stream ended unexpectedly");
                }
            }
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            panic!("Second client did not receive the broadcast within the timeout");
        }
    }

    // Close connections
    connection1.close(0u32.into(), b"done");
    endpoint1.wait_idle().await;

    connection2.close(0u32.into(), b"done");
    endpoint2.wait_idle().await;
}
