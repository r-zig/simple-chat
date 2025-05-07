use std::sync::Arc;

use async_trait::async_trait;
use chat_contract::chat;
use futures::StreamExt;
use protobuf_stream::{self, protobuf_stream::ProtobufStream};
use quinn::{RecvStream, SendStream};
use tokio::{io::BufReader, sync::Mutex};
use tracing::{debug, error};

use super::{TransportReceiver, TransportSender};

#[derive(Debug, Clone)]
pub struct QuinnTransportSender {
    send_stream: Arc<Mutex<SendStream>>,
}

impl QuinnTransportSender {
    pub fn new(send_stream: SendStream) -> Self {
        Self {
            send_stream: Arc::new(Mutex::new(send_stream)),
        }
    }
}

#[async_trait]
impl TransportSender for QuinnTransportSender {
    async fn send_message(
        &mut self,
        message: chat::ServerMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let buf: Vec<u8> = message.into();
        self.send_stream.lock().await.write_all(&buf).await?;
        Ok(())
    }
}

pub struct QuinnTransportReceiver {
    recv_stream: Option<RecvStream>,
    message_handler: Option<Box<dyn Fn(chat::ClientMessage) + Send + Sync>>,
}

impl QuinnTransportReceiver {
    pub fn new(
        recv_stream: RecvStream,
        message_handler: Box<dyn Fn(chat::ClientMessage) + Send + Sync>,
    ) -> Self {
        Self {
            recv_stream: Some(recv_stream),
            message_handler: Some(message_handler),
        }
    }
}

#[async_trait]
impl TransportReceiver for QuinnTransportReceiver {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let recv_stream = self
            .recv_stream
            .take()
            .ok_or("Receiver stream already taken")?;
        let message_handler = self
            .message_handler
            .take()
            .ok_or("Message handler already taken")?;

        tokio::spawn(async move {
            let mut client_stream = ProtobufStream::new(BufReader::new(recv_stream));
            while let Some(result) = client_stream.next().await {
                match result {
                    Ok(msg) => message_handler(msg),
                    Err(e) => error!("Error decoding message: {}", e),
                }
            }
            debug!("Stream closed");
        });

        Ok(())
    }
}
