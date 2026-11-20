//! Relay wire protocol: JSON text frames over one WebSocket per session.
//! All byte fields are base64. The relay treats `data` and `group_info` as opaque.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    App,
    Commit,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ToRelay {
    // --- first message on a connection ---
    Create {
        session_key: String,
    },
    Attach {
        room: Uuid,
        session_key: String,
    },
    Resume {
        room: Uuid,
        session_key: String,
        cursor: u64,
    },
    // --- answers to the challenge ---
    CreateFin {
        verifier: String,
        sig: String,
        group_info: String,
    },
    Auth {
        sig: String,
    },
    // --- once attached ---
    /// `after_commit` must equal the seq of the room's latest commit, or the
    /// relay answers `stale`. `id` is a random tag echoed back in the frame so
    /// the sender can recognise its own submission, including after a reconnect.
    Submit {
        id: String,
        kind: Kind,
        after_commit: u64,
        data: String,
        /// Required for commits: the group info as of after this commit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_info: Option<String>,
    },
    /// Replace the stored group info without a commit. Members use it when a
    /// sequenced commit was invalid and its group info must not be served.
    GroupInfo {
        after_commit: u64,
        data: String,
    },
    Snapshot,
    Panic,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FromRelay {
    Challenge {
        room: Uuid,
        nonce: String,
    },
    Attached {
        head: u64,
        last_commit: u64,
        group_info: String,
    },
    Resumed {
        head: u64,
    },
    Frame {
        seq: u64,
        kind: Kind,
        id: String,
        data: String,
    },
    Stale {
        id: String,
    },
    Snapshot {
        last_commit: u64,
        group_info: String,
    },
    /// The room is closed, or never existed. Terminal.
    Closed,
    /// Resume failed: the needed frames are no longer buffered.
    Gap,
    Error {
        msg: String,
    },
}
