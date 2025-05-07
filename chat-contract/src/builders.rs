use prost_types::Timestamp;
use uuid::Uuid;

use crate::{
    chat::{self, ChatMessage, Error, ErrorCode, Header, Join, Leave, MessageType},
    current_timestamp,
};

const DEFAULT_ROOM: &str = "main";

/// A builder for creating [`Header`] messages with optional defaults.
///
/// This builder helps construct a `Header` by requiring a `username` and `room`,
/// and optionally setting `message_id` and `timestamp`.
///
/// You can use `build()` for strict validation (everything must be set),
/// or `build_with_defaults()` to automatically generate a message ID and timestamp.
///
/// # Example (using default room and generated values)
/// ```
/// use chat_contract::builders::HeaderBuilder;
///
/// let header = HeaderBuilder::new()
///     .username("r-zig")
///     .with_default_room()
///     .build_with_defaults()
///     .unwrap();
/// ```
pub struct HeaderBuilder {
    username: Option<String>,
    room: Option<String>,
    timestamp: Option<Timestamp>,
    message_id: Option<String>,
}

impl HeaderBuilder {
    pub fn new() -> Self {
        Self {
            username: None,
            room: None,
            timestamp: None,
            message_id: None,
        }
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn room(mut self, room: impl Into<String>) -> Self {
        self.room = Some(room.into());
        self
    }

    pub fn with_default_room(mut self) -> Self {
        self.room = Some(DEFAULT_ROOM.to_string());
        self
    }

    pub fn timestamp(mut self, ts: Timestamp) -> Self {
        self.timestamp = Some(ts);
        self
    }

    pub fn message_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }

    /// Strict build: all fields must be provided.
    pub fn build(self) -> Result<Header, ErrorCode> {
        if self.username.as_ref().map_or(true, |s| s.trim().is_empty()) {
            return Err(ErrorCode::UsernameRequired);
        }
        if self.room.as_ref().map_or(true, |s| s.trim().is_empty()) {
            return Err(ErrorCode::RoomRequired);
        }
        if self.message_id.is_none() {
            return Err(ErrorCode::MessageIdRequired);
        }
        if self.timestamp.is_none() {
            return Err(ErrorCode::TimestampRequired);
        }

        Ok(Header {
            username: self.username.unwrap(),
            room: self.room.unwrap(),
            message_id: self.message_id.unwrap(),
            timestamp: self.timestamp,
        })
    }

    /// Lenient build: fills in missing message_id and timestamp.
    pub fn build_with_defaults(self) -> Result<Header, &'static str> {
        if self.username.as_ref().map_or(true, |s| s.trim().is_empty()) {
            return Err("username is required");
        }
        if self.room.as_ref().map_or(true, |s| s.trim().is_empty()) {
            return Err("room is required");
        }

        Ok(Header {
            username: self.username.unwrap(),
            room: self.room.unwrap(),
            message_id: self
                .message_id
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            timestamp: Some(self.timestamp.unwrap_or_else(current_timestamp)),
        })
    }
}

impl Default for HeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`Join`] message.
///
/// This builder allows you to create a `Join` message by specifying a username,
/// and optionally a room. If no room is specified, it defaults to `"custom_room"`.
///
/// The `build()` method will automatically fill in the `message_id` and `timestamp`.
///
/// # Example (with default room)
/// ```
/// use chat_contract::builders::JoinBuilder;
///
/// let join = JoinBuilder::new()
///     .username("r-zig")
///     .with_default_room()
///     .build()
///     .unwrap();
///
/// let header = join.header.unwrap();
/// assert_eq!(header.username, "r-zig");
/// assert_eq!(header.room, "main");
/// assert!(!header.message_id.is_empty());
/// assert!(header.timestamp.is_some());
/// ```
pub struct JoinBuilder {
    header_builder: HeaderBuilder,
}

impl JoinBuilder {
    pub fn new() -> Self {
        Self {
            header_builder: HeaderBuilder::new(),
        }
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.header_builder = self.header_builder.username(username.into());
        self
    }

    pub fn room(mut self, room: impl Into<String>) -> Self {
        self.header_builder = self.header_builder.room(room.into());
        self
    }

    pub fn with_default_room(mut self) -> Self {
        self.header_builder = self.header_builder.with_default_room();
        self
    }

    pub fn build(self) -> Result<Join, ErrorCode> {
        let header = self
            .header_builder
            .message_id(Uuid::new_v4().to_string())
            .timestamp(current_timestamp())
            .build()?;
        Ok(Join {
            header: Some(header),
        })
    }
}

impl Default for JoinBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`Leave`] message.
///
/// This builder allows you to create a `Leave` message by specifying a username,
/// and optionally a room. If no room is specified, it defaults to "custom_room".
///
/// The `build()` method will automatically fill in the `message_id` and `timestamp`.
///
/// # Example (with default room)
/// ```
/// use chat_contract::builders::LeaveBuilder;
///
/// let leave = LeaveBuilder::new()
///     .username("r-zig")
///     .with_default_room()
///     .build()
///     .unwrap();
///
/// let header = leave.header.unwrap();
/// assert_eq!(header.username, "r-zig");
/// assert_eq!(header.room, "main");
/// assert!(!header.message_id.is_empty());
/// assert!(header.timestamp.is_some());
/// ```
pub struct LeaveBuilder {
    header_builder: HeaderBuilder,
}

impl LeaveBuilder {
    pub fn new() -> Self {
        Self {
            header_builder: HeaderBuilder::new(),
        }
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.header_builder = self.header_builder.username(username.into());
        self
    }

    pub fn room(mut self, room: impl Into<String>) -> Self {
        self.header_builder = self.header_builder.username(room.into());
        self
    }

    pub fn with_default_room(mut self) -> Self {
        self.header_builder = self.header_builder.with_default_room();
        self
    }

    pub fn build(self) -> Result<Leave, ErrorCode> {
        let header = self
            .header_builder
            .message_id(Uuid::new_v4().to_string())
            .timestamp(current_timestamp())
            .build()?;
        Ok(Leave {
            header: Some(header),
        })
    }
}

impl Default for LeaveBuilder {
    fn default() -> Self {
        Self::new()
    }
}
/// Builder for [`ChatMessage`] message.
///
/// This builder allows you to create a `ChatMessage` by specifying a username and content,
/// and optionally a room. If no room is specified, it defaults to "custom_room".
///
/// The `build()` method will automatically fill in the `message_id` and `timestamp`.
///
/// # Example (with default room)
/// ```
/// use chat_contract::builders::ChatMessageBuilder;
///
/// let chat = ChatMessageBuilder::new()
///     .username("r-zig")
///     .with_default_room()
///     .content("Hello")
///     .build()
///     .unwrap();
///
/// let header = chat.header.unwrap();
/// assert_eq!(header.username, "r-zig");
/// assert_eq!(header.room, "main");
/// assert!(header.timestamp.is_some());
/// assert!(!header.message_id.is_empty());
/// assert_eq!(chat.content, "Hello");
/// ```
pub struct ChatMessageBuilder {
    header_builder: HeaderBuilder,
    content: Option<String>,
}

impl ChatMessageBuilder {
    pub fn new() -> Self {
        Self {
            header_builder: HeaderBuilder::new(),
            content: None,
        }
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.header_builder = self.header_builder.username(username.into());
        self
    }

    pub fn room(mut self, room: impl Into<String>) -> Self {
        self.header_builder = self.header_builder.room(room.into());
        self
    }

    pub fn with_default_room(mut self) -> Self {
        self.header_builder = self.header_builder.with_default_room();
        self
    }

    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    pub fn build(self) -> Result<ChatMessage, ErrorCode> {
        let header = self
            .header_builder
            .message_id(Uuid::new_v4().to_string())
            .timestamp(current_timestamp())
            .build()?;
        Ok(ChatMessage {
            header: Some(header),
            content: self.content.ok_or(ErrorCode::ContentRequired)?,
        })
    }
}

impl Default for ChatMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`ServerMessage`] message.
///
/// This builder allows you to create a `ServerMessage` by specifying either an error
/// or a chat message, but not both. The `build()` method will enforce this constraint.
///
/// # Example (with chat message)
/// ```
/// use chat_contract::builders::{ServerMessageBuilder, ChatMessageBuilder};
///
/// let chat_message = ChatMessageBuilder::new()
///     .username("r-zig")
///     .content("Hello")
///     .with_default_room()
///     .build()
///     .unwrap();
///
/// let server_message = ServerMessageBuilder::new()
///     .chat_message(chat_message)
///     .build()
///     .unwrap();
/// assert!(server_message.chat.is_some());
/// assert!(server_message.error.is_none());
/// ```
///
/// # Example (with error)
/// ```
/// use chat_contract::builders::{ServerMessageBuilder};
/// use chat_contract::chat::{Error, ErrorCode};
///
/// let error = Error {
///     message_id: "123".to_string(),
///     related_message_id: "456".to_string(),
///     r#type: 1,
///     code: ErrorCode::UsernameRequired as i32,
/// };
///
/// let server_message = ServerMessageBuilder::new()
///     .error(error)
///     .build()
///     .unwrap();
/// assert!(server_message.error.is_some());
/// assert!(server_message.chat.is_none());
/// ```
pub struct ServerMessageBuilder {
    error: Option<chat::Error>,
    chat: Option<chat::ChatMessage>,
}

impl ServerMessageBuilder {
    /// Creates a new `ServerMessageBuilder`.
    pub fn new() -> Self {
        Self {
            error: None,
            chat: None,
        }
    }

    /// Builds an ServerMessage `Error` message from the original `Header`.
    ///
    /// # Arguments
    /// - `header`: The `Header` from the original message that failed to proceed.
    /// - `error_type`: The type of message that caused the error (e.g., `MessageType::Join`).
    /// - `error_code`: The specific error code (e.g., `ErrorCode::UsernameAlreadyTaken`).
    ///
    /// # Returns
    /// An `Error` message populated with the relevant fields.
    pub fn error_from_header(
        self,
        header: &Header,
        error_type: MessageType,
        error_code: ErrorCode,
    ) -> Self {
        self.error(Error {
            message_id: uuid::Uuid::new_v4().to_string(), // Generate a unique ID for the error message
            related_message_id: header.message_id.clone(), // Use the original message ID
            r#type: error_type as i32, // Convert `MessageType` to its integer representation
            code: error_code as i32,   // Convert `ErrorCode` to its integer representation
        })
    }

    /// Sets the error for the `ServerMessage`.
    pub fn error(mut self, error: chat::Error) -> Self {
        self.error = Some(error);
        self
    }

    /// Sets the chat message for the `ServerMessage`.
    pub fn chat_message(mut self, chat_message: chat::ChatMessage) -> Self {
        self.chat = Some(chat_message);
        self
    }

    /// Builds the `ServerMessage`.
    ///
    /// Returns an error if neither an error nor a chat message is set.
    pub fn build(self) -> Result<chat::ServerMessage, &'static str> {
        if self.error.is_some() && self.chat.is_some() {
            return Err("ServerMessage cannot have both error and chat_message set");
        }

        if self.error.is_none() && self.chat.is_none() {
            return Err("ServerMessage must have either error or chat_message set");
        }

        Ok(chat::ServerMessage {
            error: self.error,
            chat: self.chat,
        })
    }
}

impl Default for ServerMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`ClientMessage`] message.
///
/// This builder allows you to create a `ClientMessage` by specifying either a join,
/// leave, or chat message payload. The `build()` method will enforce that at least
/// one payload is set.
///
/// # Example (with join payload)
/// ```
/// use chat_contract::builders::ClientMessageBuilder;
///
/// let client_message = ClientMessageBuilder::new()
///     .join("r-zig", Some("main"))
///     .build()
///     .unwrap();
/// assert!(client_message.payload.is_some());
/// ```
///
/// # Example (with chat payload)
/// ```
/// use chat_contract::builders::ClientMessageBuilder;
///
/// let client_message = ClientMessageBuilder::new()
///     .chat("r-zig", "Hello", None)
///     .build()
///     .unwrap();
/// assert!(client_message.payload.is_some());
/// ```
pub struct ClientMessageBuilder {
    join_builder: Option<JoinBuilder>,
    leave_builder: Option<LeaveBuilder>,
    chat_message_builder: Option<ChatMessageBuilder>,
}

impl ClientMessageBuilder {
    /// Creates a new `ClientMessageBuilder`.
    pub fn new() -> Self {
        Self {
            join_builder: None,
            leave_builder: None,
            chat_message_builder: None,
        }
    }

    /// Sets the `Join` payload using a `JoinBuilder`.
    pub fn join(mut self, username: impl Into<String>, room: Option<&str>) -> Self {
        let mut builder = JoinBuilder::new().username(username);
        if let Some(room) = room {
            builder = builder.room(room);
        } else {
            builder = builder.with_default_room();
        }
        self.join_builder = Some(builder);
        self
    }

    /// Sets the `Leave` payload using a `LeaveBuilder`.
    pub fn leave(mut self, username: impl Into<String>, room: Option<String>) -> Self {
        let mut builder = LeaveBuilder::new().username(username);
        if let Some(room) = room {
            builder = builder.room(room);
        } else {
            builder = builder.with_default_room();
        }
        self.leave_builder = Some(builder);
        self
    }

    /// Sets the `ChatMessage` payload using a `ChatMessageBuilder`.
    pub fn chat(
        mut self,
        username: impl Into<String>,
        content: impl Into<String>,
        room: Option<&str>,
    ) -> Self {
        let mut builder = ChatMessageBuilder::new()
            .username(username)
            .content(content);
        if let Some(room) = room {
            builder = builder.room(room);
        } else {
            builder = builder.with_default_room();
        }
        self.chat_message_builder = Some(builder);
        self
    }

    /// Builds the `ClientMessage`.
    ///
    /// Returns an error if no payload is set.
    pub fn build(self) -> Result<chat::ClientMessage, &'static str> {
        let payload = self
            .join_builder
            .map(|builder| chat::client_message::Payload::Join(builder.build().unwrap()))
            .or_else(|| {
                self.leave_builder
                    .map(|builder| chat::client_message::Payload::Leave(builder.build().unwrap()))
            })
            .or_else(|| {
                self.chat_message_builder
                    .map(|builder| chat::client_message::Payload::Chat(builder.build().unwrap()))
            });

        if let Some(payload) = payload {
            Ok(chat::ClientMessage {
                payload: Some(payload),
            })
        } else {
            Err("ClientMessage must have at least one payload set")
        }
    }
}

impl Default for ClientMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::current_timestamp;

    use super::*;
    #[test]
    fn build_header_strict_success() {
        let header = HeaderBuilder::new()
            .username("r-zig")
            .room("custom_room")
            .message_id("custom-id-123")
            .timestamp(current_timestamp())
            .build()
            .expect("should build successfully");

        assert_eq!(header.username, "r-zig");
        assert_eq!(header.room, "custom_room");
        assert_eq!(header.message_id, "custom-id-123");
        assert!(header.timestamp.is_some());
    }

    #[test]
    fn build_header_strict_missing_username() {
        let result = HeaderBuilder::new()
            .room("custom_room")
            .message_id("id")
            .timestamp(current_timestamp())
            .build();

        assert_eq!(result, Err(ErrorCode::UsernameRequired));
    }

    #[test]
    fn build_header_strict_missing_room() {
        let result = HeaderBuilder::new()
            .username("r-zig")
            .message_id("id")
            .timestamp(current_timestamp())
            .build();

        assert_eq!(result, Err(ErrorCode::RoomRequired));
    }

    #[test]
    fn build_header_strict_missing_message_id() {
        let result = HeaderBuilder::new()
            .username("r-zig")
            .room("custom_room")
            .timestamp(current_timestamp())
            .build();

        assert_eq!(result, Err(ErrorCode::MessageIdRequired));
    }

    #[test]
    fn build_header_strict_missing_timestamp() {
        let result = HeaderBuilder::new()
            .username("r-zig")
            .room("custom_room")
            .message_id("id")
            .build();

        assert_eq!(result, Err(ErrorCode::TimestampRequired));
    }

    #[test]
    fn build_header_with_defaults_success() {
        let header = HeaderBuilder::new()
            .username("r-zig")
            .with_default_room()
            .build_with_defaults()
            .expect("should build successfully");

        assert_eq!(header.username, "r-zig");
        assert_eq!(header.room, DEFAULT_ROOM);
        assert!(header.message_id.len() > 10);
        assert!(header.timestamp.is_some());
    }

    #[test]
    fn build_header_with_defaults_missing_username() {
        let result = HeaderBuilder::new()
            .with_default_room()
            .build_with_defaults();

        assert_eq!(result, Err("username is required"));
    }

    #[test]
    fn build_header_with_defaults_missing_room() {
        let result = HeaderBuilder::new().username("r-zig").build_with_defaults();

        assert_eq!(result, Err("room is required"));
    }

    #[test]
    fn join_builder_sets_username_and_room() {
        let join = JoinBuilder::new()
            .username("r-zig")
            .room("custom_room")
            .build()
            .unwrap();
        assert_eq!(join.header.as_ref().unwrap().username, "r-zig");
        assert_eq!(join.header.as_ref().unwrap().room, "custom_room");
    }

    #[test]
    fn leave_builder_default_room() {
        let leave = LeaveBuilder::new()
            .username("r-zig")
            .with_default_room()
            .build()
            .unwrap();
        assert_eq!(leave.header.as_ref().unwrap().room, DEFAULT_ROOM);
    }

    #[test]
    fn chat_message_builder_success() {
        let chat = ChatMessageBuilder::new()
            .username("r-zig")
            .content("Hello")
            .with_default_room()
            .build()
            .unwrap();
        assert_eq!(chat.content, "Hello");
        assert_eq!(chat.header.as_ref().unwrap().room, DEFAULT_ROOM);
    }

    #[test]
    fn chat_message_missing_content() {
        let result = ChatMessageBuilder::new()
            .username("r-zig")
            .with_default_room()
            .build();
        assert_eq!(result, Err(ErrorCode::ContentRequired));
    }

    #[test]
    fn server_message_builder_with_chat_message() {
        let chat_message = ChatMessageBuilder::new()
            .username("r-zig")
            .content("Hello")
            .with_default_room()
            .build()
            .unwrap();

        let server_message = ServerMessageBuilder::new()
            .chat_message(chat_message)
            .build()
            .unwrap();

        assert!(server_message.chat.is_some());
        assert!(server_message.error.is_none());
    }

    #[test]
    fn server_message_builder_with_error() {
        let error = chat::Error {
            message_id: "123".to_string(),
            related_message_id: "456".to_string(),
            r#type: 1,
            code: ErrorCode::UsernameRequired as i32,
        };

        let server_message = ServerMessageBuilder::new().error(error).build().unwrap();

        assert!(server_message.error.is_some());
        assert!(server_message.chat.is_none());
    }

    #[test]
    fn server_message_builder_error_when_both_set() {
        let chat_message = ChatMessageBuilder::new()
            .username("r-zig")
            .content("Hello")
            .with_default_room()
            .build()
            .unwrap();

        let error = chat::Error {
            message_id: "123".to_string(),
            related_message_id: "456".to_string(),
            r#type: 1,
            code: ErrorCode::UsernameRequired as i32,
        };

        let result = ServerMessageBuilder::new()
            .chat_message(chat_message)
            .error(error)
            .build();

        assert_eq!(
            result,
            Err("ServerMessage cannot have both error and chat_message set")
        );
    }

    #[test]
    fn server_message_builder_error_when_none_set() {
        let result = ServerMessageBuilder::new().build();

        assert_eq!(
            result,
            Err("ServerMessage must have either error or chat_message set")
        );
    }

    #[test]
    fn server_message_builder_error_from_header() {
        // Create a mock header
        let header = Header {
            username: "test_user".to_string(),
            room: "test_room".to_string(),
            message_id: "original-message-id".to_string(),
            timestamp: Some(current_timestamp()),
        };

        // Build an error message using `error_from_header`
        let server_message = ServerMessageBuilder::new()
            .error_from_header(&header, MessageType::Join, ErrorCode::UsernameAlreadyTaken)
            .build()
            .unwrap();

        // Assert that the error is correctly populated
        let error = server_message.error.unwrap();
        assert_eq!(error.related_message_id, "original-message-id");
        assert_eq!(error.r#type, MessageType::Join as i32);
        assert_eq!(error.code, ErrorCode::UsernameAlreadyTaken as i32);
        assert!(!error.message_id.is_empty()); // Ensure a unique message ID is generated
    }

    #[test]
    fn build_client_message_with_join() {
        let join_message = ClientMessageBuilder::new()
            .join("test_user", Some("test_room"))
            .build()
            .unwrap();

        assert!(matches!(
            join_message.payload,
            Some(chat::client_message::Payload::Join(_))
        ));
    }

    #[test]
    fn build_client_message_with_leave() {
        let leave_message = ClientMessageBuilder::new()
            .leave("test_user", None) // Defaults to the default room
            .build()
            .unwrap();

        assert!(matches!(
            leave_message.payload,
            Some(chat::client_message::Payload::Leave(_))
        ));
    }

    #[test]
    fn build_client_message_with_chat() {
        let chat_message = ClientMessageBuilder::new()
            .chat("test_user", "Hello, world!", Some("test_room"))
            .build()
            .unwrap();

        assert!(matches!(
            chat_message.payload,
            Some(chat::client_message::Payload::Chat(_))
        ));
    }

    #[test]
    fn build_client_message_without_payload() {
        let result = ClientMessageBuilder::new().build();
        assert_eq!(
            result,
            Err("ClientMessage must have at least one payload set")
        );
    }
}
