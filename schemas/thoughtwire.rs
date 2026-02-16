// Thoughtwire Protocol — Rust Types
// Auto-generated from protocol.py
// DO NOT EDIT — regenerate with: thoughtwire schema --format rust
// Generated: 2026-02-16 20:04:37 UTC

pub const VERSION_1: u8 = 1;
pub const VERSION_2: u8 = 2;
pub const MAX_PAYLOAD: usize = 65535;
pub const V1_HEADER_SIZE: usize = 14;
pub const V2_HEADER_SIZE: usize = 16;
pub const ED25519_SIG_SIZE: usize = 64;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {
    Chat = 0,
    Vote = 1,
    StateDiff = 2,
    Attention = 3,
    System = 4,
    Heartbeat = 5,
    Error = 6,
    Ack = 7,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Intent {
    Inform = 0,
    Request = 1,
    Propose = 2,
    Approve = 3,
    Reject = 4,
    Respond = 5,
    Query = 6,
    Delegate = 7,
}

/// V1 frame header (14 bytes, network byte order)
#[repr(C, packed)]
pub struct FrameV1Header {
    pub version: u8,
    pub frame_type: u8,
    pub agent_id: u32,
    pub timestamp: u32,
    pub confidence: u8,
    pub intent: u8,
    pub payload_len: i16,
}

/// V2 frame header (16 bytes, network byte order)
#[repr(C, packed)]
pub struct FrameV2Header {
    pub version: u8,
    pub frame_type: u8,
    pub agent_id: u32,
    pub timestamp: u32,
    pub confidence: u8,
    pub intent: u8,
    pub payload_len: i16,
    pub sig_len: u16,
}

/// Decoded frame
#[derive(Debug)]
pub struct Frame {
    pub version: u8,
    pub frame_type: FrameType,
    pub agent_id: u32,
    pub timestamp: u32,
    pub confidence: f32,
    pub intent: Intent,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub signed: bool,
    pub verified: bool,
}

impl Frame {
    /// Decode confidence byte to float
    pub fn decode_confidence(raw: u8) -> f32 {
        raw as f32 / 255.0
    }

    /// Encode confidence float to byte
    pub fn encode_confidence(conf: f32) -> u8 {
        (conf.clamp(0.0, 1.0) * 255.0) as u8
    }
}
