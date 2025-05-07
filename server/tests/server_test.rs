use chat_contract::{
    builders::ClientMessageBuilder,
    chat::{ErrorCode, MessageType, ServerMessage},
};
use futures::{StreamExt, TryStreamExt};
use protobuf_stream::protobuf_stream::ProtobufStream;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
use rustls_pki_types::CertificateDer;
use std::{fs, sync::Arc};
use tokio::io::BufReader;

fn get_client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();

    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    let cert = fs::read(dirs.data_local_dir().join("cert.der")).unwrap();
    roots.add(CertificateDer::from(cert))?;

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    Ok(client_config)
}

const DEFAULT_SERVER_ADDRESS: &str = "[::1]:4433";

async fn connect_to_server() -> Result<(quinn::Connection, Endpoint), quinn::ConnectionError> {
    // Configure the client
    let client_config = get_client_config().unwrap();

    let listen_addr = "[::1]:0".parse().unwrap(); // Bind to any available port
    let mut endpoint = quinn::Endpoint::client(listen_addr).unwrap();
    endpoint.set_default_client_config(client_config);

    // Connect to the server
    let connection = endpoint
        .connect(DEFAULT_SERVER_ADDRESS.parse().unwrap(), "localhost")
        .unwrap()
        .await?;
    Ok((connection, endpoint))
}

#[tokio::test]
async fn test_server_accepts_connection() {
    let (connection, endpoint) = connect_to_server()
        .await
        .expect("Failed to connect to server");
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

    // Send the `Join` message
    let buf: Vec<u8> = client_message.into();
    send_stream.write_all(&buf).await.unwrap();

    // Send twice to receive the server's error response UsernameAlreadyTaken
    send_stream.write_all(&buf).await.unwrap();
    send_stream.finish().unwrap();
    // Read the server's response
    let reader = BufReader::new(recv_stream);
    let mut stream = ProtobufStream::<_, ServerMessage>::new(reader);

    if let Some(response) = stream.next().await {
        let error = response.unwrap().error.unwrap();
        assert_eq!(error.r#type, MessageType::Join as i32);
        assert_eq!(error.code, ErrorCode::UsernameAlreadyTaken as i32);
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
}
