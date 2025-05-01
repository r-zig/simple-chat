// Include the generated Rust code from the .proto definitions
pub mod chat {
    include!(concat!(env!("OUT_DIR"), "/chat.rs"));
}

use chat::Header;
pub use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
pub mod builders;

/// Create a new Header with current timestamp and a random message ID
pub fn generate_header(username: &str, room: &str) -> Header {
    Header {
        message_id: Uuid::new_v4().to_string(),
        username: username.to_owned(),
        room: room.to_owned(),
        timestamp: Some(current_timestamp()),
    }
}

/// Return the current time as a prost_types::Timestamp
pub fn current_timestamp() -> Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}

/// Validate a Header according to current rules:
/// - username must not be empty
/// - room must not be empty
/// - timestamp must be present
pub fn validate_header(header: &Header) -> Result<(), &'static str> {
    if header.username.trim().is_empty() {
        return Err("Username is empty");
    }
    if header.room.trim().is_empty() {
        return Err("Room name is empty");
    }
    if header.timestamp.is_none() {
        return Err("Missing timestamp");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_header_has_values() {
        let username = "r-zig";
        let room = "general";
        let header = generate_header(username, room);

        assert_eq!(header.username, username);
        assert_eq!(header.room, room);
        assert!(header.message_id.len() > 10, "message_id should be a UUID");
        assert!(header.timestamp.is_some(), "timestamp should be set");
    }

    #[test]
    fn test_validate_header_success() {
        let header = generate_header("r-zig", "general");
        let result = validate_header(&header);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_header_empty_username() {
        let mut header = generate_header("", "general");
        header.username.clear(); // explicitly empty
        let result = validate_header(&header);
        assert_eq!(result, Err("Username is empty"));
    }

    #[test]
    fn test_validate_header_empty_room() {
        let mut header = generate_header("r-zig", "");
        header.room.clear(); // explicitly empty
        let result = validate_header(&header);
        assert_eq!(result, Err("Room name is empty"));
    }

    #[test]
    fn test_validate_header_missing_timestamp() {
        let mut header = generate_header("r-zig", "general");
        header.timestamp = None;
        let result = validate_header(&header);
        assert_eq!(result, Err("Missing timestamp"));
    }
}
