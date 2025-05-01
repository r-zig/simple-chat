use prost_types::Timestamp;
use uuid::Uuid;

use crate::{chat::Header, current_timestamp};

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
    pub fn build(self) -> Result<Header, &'static str> {
        if self.username.as_ref().map_or(true, |s| s.trim().is_empty()) {
            return Err("username is required");
        }
        if self.room.as_ref().map_or(true, |s| s.trim().is_empty()) {
            return Err("room is required");
        }
        if self.message_id.is_none() {
            return Err("message_id is required");
        }
        if self.timestamp.is_none() {
            return Err("timestamp is required");
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

#[cfg(test)]
mod tests {
    use crate::current_timestamp;

    use super::*;
    #[test]
    fn build_header_strict_success() {
        let header = HeaderBuilder::new()
            .username("r-zig")
            .room("main")
            .message_id("custom-id-123")
            .timestamp(current_timestamp())
            .build()
            .expect("should build successfully");

        assert_eq!(header.username, "r-zig");
        assert_eq!(header.room, "main");
        assert_eq!(header.message_id, "custom-id-123");
        assert!(header.timestamp.is_some());
    }

    #[test]
    fn build_header_strict_missing_username() {
        let result = HeaderBuilder::new()
            .room("main")
            .message_id("id")
            .timestamp(current_timestamp())
            .build();

        assert_eq!(result, Err("username is required"));
    }

    #[test]
    fn build_header_strict_missing_room() {
        let result = HeaderBuilder::new()
            .username("r-zig")
            .message_id("id")
            .timestamp(current_timestamp())
            .build();

        assert_eq!(result, Err("room is required"));
    }

    #[test]
    fn build_header_strict_missing_message_id() {
        let result = HeaderBuilder::new()
            .username("r-zig")
            .room("main")
            .timestamp(current_timestamp())
            .build();

        assert_eq!(result, Err("message_id is required"));
    }

    #[test]
    fn build_header_strict_missing_timestamp() {
        let result = HeaderBuilder::new()
            .username("r-zig")
            .room("main")
            .message_id("id")
            .build();

        assert_eq!(result, Err("timestamp is required"));
    }

    #[test]
    fn build_header_with_defaults_success() {
        let header = HeaderBuilder::new()
            .username("r-zig")
            .with_default_room()
            .build_with_defaults()
            .expect("should build successfully");

        assert_eq!(header.username, "r-zig");
        assert_eq!(header.room, "main");
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
}
