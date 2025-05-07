use actix::Message;
use chat_contract::chat;
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio::sync::Mutex; // Protobuf types

use crate::transport::TransportSender;

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
pub struct Join<T>
where
    T: TransportSender + Clone + Unpin,
{
    inner: chat::Join,
    pub sender: Arc<Mutex<T>>,
}

impl<T> Join<T>
where
    T: TransportSender + Clone + Unpin,
{
    pub fn new(inner: chat::Join, sender: Arc<Mutex<T>>) -> Self {
        Self { inner, sender }
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
pub struct Leave {
    inner: chat::Leave,
}
impl Leave {
    pub(crate) fn new(leave: chat::Leave) -> Self {
        Self { inner: leave }
    }
}

#[derive(Message, Debug, Clone)]
#[rtype(result = "()")]
pub struct ChatMessage {
    inner: chat::ChatMessage,
}

impl ChatMessage {
    pub(crate) fn new(chat_message: chat::ChatMessage) -> Self {
        Self {
            inner: chat_message,
        }
    }

    pub fn inner(&self) -> &chat::ChatMessage {
        &self.inner
    }
}
// Implement Deref to expose fields of the inner Protobuf type
impl<T> Deref for Join<T>
where
    T: TransportSender + Clone + Unpin,
{
    type Target = chat::Join;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Join<T>
where
    T: TransportSender + Clone + Unpin,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Deref for Leave {
    type Target = chat::Leave;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Leave {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Deref for ChatMessage {
    type Target = chat::ChatMessage;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ChatMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
