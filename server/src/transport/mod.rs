use std::fmt::Debug;

use async_trait::async_trait;
use chat_contract::chat;
mod quic;

pub use quic::{QuinnTransportReceiver, QuinnTransportSender};

#[async_trait]
pub trait TransportSender: Send + Sync + 'static + Debug {
    /// Sends a Protobuf `ServerMessage` to the client.
    async fn send_message(
        &mut self,
        message: chat::ServerMessage,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait]
pub trait TransportReceiver: Send + Sync + 'static {
    /// Starts listening for incoming `ClientMessage` and forwards them to the provided handler.
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;
}
