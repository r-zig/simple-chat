use crate::messages::{ChatMessage, Join, Leave};
use crate::transport::TransportSender;
use actix::prelude::*;
use chat_contract::builders::{ChatMessageBuilder, ServerMessageBuilder};
use chat_contract::chat::{ErrorCode, MessageType, ServerMessage};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, warn};

pub struct ChatActor<T: TransportSender> {
    users: HashMap<String, Arc<Mutex<T>>>, // Username -> TransportSender
}

impl<T: TransportSender + Clone> Default for ChatActor<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: TransportSender + Clone> ChatActor<T> {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Broadcast message to all users in the room except the excluded user.
    fn broadcast(&mut self, msg: ServerMessage, exclude_user: Option<&str>) {
        self.users
            .iter()
            .filter(|(user, _)| exclude_user.map_or(true, |exclude| user != &exclude)) // Exclude the user if specified
            .for_each(|(user, user_sender)| {
                let user_sender = user_sender.clone(); // Clone the sender for async move
                let msg = msg.clone(); // Clone the message for async move
                let user = user.clone(); // Clone the username for logging

                actix::spawn(async move {
                    if let Err(e) = user_sender.lock().await.send_message(msg).await {
                        error!("Failed to send message to {}: {}", user, e);
                    }
                });
            });
    }
}

// Implement the Actor trait for ChatActor
impl<T: TransportSender + Unpin> Actor for ChatActor<T> {
    type Context = Context<Self>;
}

impl<T: TransportSender + Unpin + Clone> Handler<Join<T>> for ChatActor<T> {
    type Result = ();

    fn handle(&mut self, msg: Join<T>, _: &mut Context<Self>) {
        let username = msg.header.as_ref().unwrap().username.clone();

        match self.users.contains_key(&username) {
            true => {
                warn!("User {} already exists", username);
                // Build the error message
                let server_message = ServerMessageBuilder::new()
                    .error_from_header(
                        msg.header.as_ref().unwrap(),
                        MessageType::Join,
                        ErrorCode::UsernameAlreadyTaken,
                    )
                    .build()
                    .unwrap();

                // Send the error message back to the client
                let sender = msg.sender.clone();
                actix::spawn(async move {
                    if let Err(e) = sender.lock().await.send_message(server_message).await {
                        error!("Failed to send error message to {}: {}", username, e);
                    }
                });
            }
            false => {
                // Add the user to the users map
                let sender = msg.sender.clone();
                // Associate the user with their TransportSender
                self.users.insert(username.clone(), sender);

                debug!("User {} joined", username);
                let server_message = ServerMessageBuilder::new()
                    .chat_message(
                        ChatMessageBuilder::new()
                            .username(username.clone())
                            .with_default_room()
                            .content(format!("User {} has joined the room", username))
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap();
                self.broadcast(server_message, Some(&username));
            }
        }
    }
}

impl<T: TransportSender + Unpin + Clone> Handler<Leave> for ChatActor<T> {
    type Result = ();

    fn handle(&mut self, msg: Leave, _: &mut Context<Self>) {
        let username = msg.header.as_ref().unwrap().username.clone();

        // Remove the user from the room
        if self.users.remove(&username).is_some() {
            let server_message = ServerMessageBuilder::new()
                .chat_message(
                    ChatMessageBuilder::new()
                        .username(username.clone())
                        .with_default_room()
                        .content(format!("User {} has left the room", username))
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap();
            self.broadcast(server_message, Some(&username));

            debug!(
                "User {} left. room contains {} users",
                username,
                self.users.len()
            );
        }
    }
}

impl<T: TransportSender + Unpin + Clone> Handler<ChatMessage> for ChatActor<T> {
    type Result = ();

    fn handle(&mut self, msg: ChatMessage, _: &mut Context<Self>) {
        let username = msg.header.as_ref().unwrap().username.clone();
        let room = msg.header.as_ref().unwrap().room.clone();
        let content = msg.content.clone();

        debug!(
            "User {} sent message in room {}: {}",
            username, room, content
        );

        let server_message = ServerMessageBuilder::new()
            .chat_message(msg.inner().clone())
            .build()
            .unwrap();
        self.broadcast(server_message, Some(&username));
    }
}
