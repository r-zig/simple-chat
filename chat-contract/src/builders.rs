use prost_types::Timestamp;
use uuid::Uuid;

use crate::{
    chat::{ChatMessage, ErrorCode, Header, Join, Leave},
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
    username: Option<String>,
    room: Option<String>,
}

impl JoinBuilder {
    pub fn new() -> Self {
        Self {
            username: None,
            room: Some(DEFAULT_ROOM.to_string()),
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

    pub fn build(self) -> Result<Join, ErrorCode> {
        let header = Header {
            username: self.username.ok_or(ErrorCode::UsernameRequired)?,
            room: self.room.ok_or(ErrorCode::RoomRequired)?,
            message_id: Uuid::new_v4().to_string(),
            timestamp: Some(current_timestamp()),
        };
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
    username: Option<String>,
    room: Option<String>,
}

impl LeaveBuilder {
    pub fn new() -> Self {
        Self {
            username: None,
            room: Some(DEFAULT_ROOM.to_string()),
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

    pub fn build(self) -> Result<Leave, ErrorCode> {
        let header = Header {
            username: self.username.ok_or(ErrorCode::UsernameRequired)?,
            room: self.room.ok_or(ErrorCode::RoomRequired)?,
            message_id: Uuid::new_v4().to_string(),
            timestamp: Some(current_timestamp()),
        };
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
    username: Option<String>,
    room: Option<String>,
    content: Option<String>,
}

impl ChatMessageBuilder {
    pub fn new() -> Self {
        Self {
            username: None,
            room: Some(DEFAULT_ROOM.to_string()),
            content: None,
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

    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    pub fn build(self) -> Result<ChatMessage, ErrorCode> {
        Ok(ChatMessage {
            header: Some(Header {
                username: self.username.ok_or(ErrorCode::UsernameRequired)?,
                room: self.room.ok_or(ErrorCode::RoomRequired)?,
                message_id: Uuid::new_v4().to_string(),
                timestamp: Some(current_timestamp()),
            }),
            content: self.content.ok_or(ErrorCode::ContentRequired)?,
        })
    }
}

impl Default for ChatMessageBuilder {
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
        let leave = LeaveBuilder::new().username("r-zig").build().unwrap();
        assert_eq!(leave.header.as_ref().unwrap().room, DEFAULT_ROOM);
    }

    #[test]
    fn chat_message_builder_success() {
        let chat = ChatMessageBuilder::new()
            .username("r-zig")
            .content("Hello")
            .build()
            .unwrap();
        assert_eq!(chat.content, "Hello");
        assert_eq!(chat.header.as_ref().unwrap().room, DEFAULT_ROOM);
    }

    #[test]
    fn chat_message_missing_content() {
        let result = ChatMessageBuilder::new().username("r-zig").build();
        assert_eq!(result, Err(ErrorCode::ContentRequired));
    }
}
