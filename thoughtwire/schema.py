"""
Thoughtwire Schema Generator — Auto-generate serialization schemas from PROTOCOL.md.

Generates protobuf, flatbuffers, and JSON Schema from the canonical protocol definition.
Source of truth is always protocol.py — schemas are derived, never hand-maintained.
"""

import json
import time
from .protocol import (
    FRAME_TYPES, INTENTS, CHANNELS, AGENTS,
    VERSION_1, VERSION_2, MAX_PAYLOAD, MAX_CHANNEL_LEN,
)


def generate_protobuf() -> str:
    """Generate a .proto file from protocol constants."""
    # Build enum entries
    ft_entries = "\n".join(f"    {k.upper()} = {v};" for k, v in sorted(FRAME_TYPES.items(), key=lambda x: x[1]))
    intent_entries = "\n".join(f"    {k.upper()} = {v};" for k, v in sorted(INTENTS.items(), key=lambda x: x[1]))
    channel_entries = "\n".join(f"    {k.upper().replace('-', '_')} = {v};" for k, v in sorted(CHANNELS.items(), key=lambda x: x[1]))
    
    agent_comments = "\n".join(f"//   {name} = 0x{aid:08X}" for name, aid in sorted(AGENTS.items(), key=lambda x: x[1]))

    return f'''// Thoughtwire Protocol — Auto-generated from protocol.py
// DO NOT EDIT — regenerate with: thoughtwire schema --format protobuf
// Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
//
// Source: https://github.com/flint-dominic/thoughtwire

syntax = "proto3";

package thoughtwire;

option go_package = "github.com/flint-dominic/thoughtwire/proto";
option java_package = "com.thoughtwire.proto";

// ── Frame Types ──────────────────────────────────────────────────

enum FrameType {{
{ft_entries}
}}

// ── Intents ──────────────────────────────────────────────────────

enum Intent {{
{intent_entries}
}}

// ── Channels ─────────────────────────────────────────────────────

enum Channel {{
{channel_entries}
}}

// ── Known Agents ─────────────────────────────────────────────────
// Agent IDs are uint32. Known agents:
{agent_comments}

// ── Frame (v1) ───────────────────────────────────────────────────
// Wire format: 14-byte packed header + variable payload
// This protobuf is for interchange/tooling, NOT the wire format.

message Frame {{
    uint32 version = 1;        // Protocol version (1 or 2)
    FrameType frame_type = 2;  // Frame type enum
    uint32 agent_id = 3;       // Agent identifier
    uint32 timestamp = 4;      // Unix timestamp (truncated to uint32)
    float confidence = 5;      // 0.0-1.0 (wire: uint8 0-255)
    Intent intent = 6;         // Intent enum
    bytes payload = 7;         // Variable payload (max {MAX_PAYLOAD} bytes)
    
    // v2 signing fields
    bytes signature = 8;       // Ed25519 signature (64 bytes, empty if unsigned)
    bool signed = 9;           // Whether frame carries a signature
    bool verified = 10;        // Whether signature was verified
}}

// ── MQTT Topics ──────────────────────────────────────────────────
// Not expressible in protobuf, documented here for reference:
//
//   egregore/council/{{channel}}       — Council discussion
//   egregore/agent/{{id}}/response     — Agent responses
//   egregore/direct/{{from}}/{{to}}       — Direct messages
//   egregore/system/{{event}}          — System events
//   egregore/votes/{{proposal}}        — Governance votes
//   egregore/keys/{{agent}}            — Public key announcements

// ── Batch ────────────────────────────────────────────────────────

message FrameBatch {{
    repeated Frame frames = 1;
    uint32 count = 2;
}}

// ── Key Exchange ─────────────────────────────────────────────────

message PublicKey {{
    string agent_name = 1;
    uint32 agent_id = 2;
    bytes public_key = 3;      // Ed25519 public key (32 bytes)
    uint32 timestamp = 4;      // When key was generated
}}

message KeyRing {{
    repeated PublicKey keys = 1;
}}
'''


def generate_flatbuffers() -> str:
    """Generate a .fbs FlatBuffers schema."""
    ft_entries = "\n".join(f"    {k.upper()} = {v}," for k, v in sorted(FRAME_TYPES.items(), key=lambda x: x[1]))
    intent_entries = "\n".join(f"    {k.upper()} = {v}," for k, v in sorted(INTENTS.items(), key=lambda x: x[1]))

    return f'''// Thoughtwire Protocol — FlatBuffers Schema
// Auto-generated from protocol.py
// DO NOT EDIT — regenerate with: thoughtwire schema --format flatbuffers
// Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}

namespace Thoughtwire;

enum FrameType : ubyte {{
{ft_entries}
}}

enum Intent : ubyte {{
{intent_entries}
}}

table Frame {{
    version: ubyte = 1;
    frame_type: FrameType;
    agent_id: uint32;
    timestamp: uint32;
    confidence: ubyte;          // 0-255 maps to 0.0-1.0
    intent: Intent;
    payload: [ubyte];           // max {MAX_PAYLOAD} bytes
    signature: [ubyte];         // Ed25519 (64 bytes) or empty
}}

table FrameBatch {{
    frames: [Frame];
}}

table PublicKey {{
    agent_name: string;
    agent_id: uint32;
    public_key: [ubyte];        // 32 bytes Ed25519
    timestamp: uint32;
}}

root_type Frame;
'''


def generate_json_schema() -> dict:
    """Generate JSON Schema for the frame format."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/flint-dominic/thoughtwire/frame.schema.json",
        "title": "Thoughtwire Frame",
        "description": f"Auto-generated from protocol.py — {time.strftime('%Y-%m-%d')}",
        "type": "object",
        "required": ["version", "frame_type", "agent_id", "timestamp", "confidence", "intent"],
        "properties": {
            "version": {
                "type": "integer",
                "enum": [VERSION_1, VERSION_2],
                "description": "Protocol version"
            },
            "frame_type": {
                "type": "string",
                "enum": list(FRAME_TYPES.keys()),
                "description": "Frame type"
            },
            "agent_id": {
                "type": "integer",
                "minimum": 0,
                "maximum": 4294967295,
                "description": "Agent identifier (uint32)"
            },
            "timestamp": {
                "type": "integer",
                "minimum": 0,
                "maximum": 4294967295,
                "description": "Unix timestamp (uint32)"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence level"
            },
            "intent": {
                "type": "string",
                "enum": list(INTENTS.keys()),
                "description": "Intent type"
            },
            "payload": {
                "type": "string",
                "maxLength": MAX_PAYLOAD,
                "description": "Payload text (UTF-8)"
            },
            "signed": {
                "type": "boolean",
                "description": "Whether frame carries a signature"
            },
            "verified": {
                "type": "boolean",
                "description": "Whether signature was verified"
            },
            "signature": {
                "type": "string",
                "description": "Ed25519 signature (hex-encoded)"
            }
        }
    }


def generate_c_header() -> str:
    """Generate a C header file for embedding in native code."""
    ft_defines = "\n".join(f"#define TW_FRAME_{k.upper()} {v}" for k, v in sorted(FRAME_TYPES.items(), key=lambda x: x[1]))
    intent_defines = "\n".join(f"#define TW_INTENT_{k.upper()} {v}" for k, v in sorted(INTENTS.items(), key=lambda x: x[1]))
    agent_defines = "\n".join(f"#define TW_AGENT_{k.upper()} 0x{v:08X}U" for k, v in sorted(AGENTS.items(), key=lambda x: x[1]))

    return f'''/*
 * Thoughtwire Protocol — C Header
 * Auto-generated from protocol.py
 * DO NOT EDIT — regenerate with: thoughtwire schema --format c
 * Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
 */

#ifndef THOUGHTWIRE_H
#define THOUGHTWIRE_H

#include <stdint.h>

#define TW_VERSION_1 1
#define TW_VERSION_2 2
#define TW_MAX_PAYLOAD {MAX_PAYLOAD}
#define TW_V1_HEADER_SIZE 14
#define TW_V2_HEADER_SIZE 16
#define TW_ED25519_SIG_SIZE 64

/* Frame Types */
{ft_defines}

/* Intents */
{intent_defines}

/* Known Agents */
{agent_defines}

/* V1 Frame Header (14 bytes, packed, network byte order) */
typedef struct __attribute__((packed)) {{
    uint8_t  version;
    uint8_t  frame_type;
    uint32_t agent_id;
    uint32_t timestamp;
    uint8_t  confidence;    /* 0-255 → 0.0-1.0 */
    uint8_t  intent;
    int16_t  payload_len;
}} tw_frame_v1_t;

/* V2 Frame Header (16 bytes, packed, network byte order) */
typedef struct __attribute__((packed)) {{
    uint8_t  version;
    uint8_t  frame_type;
    uint32_t agent_id;
    uint32_t timestamp;
    uint8_t  confidence;
    uint8_t  intent;
    int16_t  payload_len;
    uint16_t sig_len;       /* 0 = unsigned, 64 = Ed25519 */
}} tw_frame_v2_t;

/* Decode confidence byte to float */
static inline float tw_confidence(uint8_t raw) {{
    return raw / 255.0f;
}}

/* Encode confidence float to byte */
static inline uint8_t tw_encode_confidence(float conf) {{
    if (conf < 0.0f) conf = 0.0f;
    if (conf > 1.0f) conf = 1.0f;
    return (uint8_t)(conf * 255.0f);
}}

#endif /* THOUGHTWIRE_H */
'''


def generate_rust() -> str:
    """Generate Rust type definitions."""
    ft_variants = "\n".join(f"    {k.title().replace('_', '')} = {v}," for k, v in sorted(FRAME_TYPES.items(), key=lambda x: x[1]))
    intent_variants = "\n".join(f"    {k.title().replace('_', '')} = {v}," for k, v in sorted(INTENTS.items(), key=lambda x: x[1]))

    return f'''// Thoughtwire Protocol — Rust Types
// Auto-generated from protocol.py
// DO NOT EDIT — regenerate with: thoughtwire schema --format rust
// Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}

pub const VERSION_1: u8 = {VERSION_1};
pub const VERSION_2: u8 = {VERSION_2};
pub const MAX_PAYLOAD: usize = {MAX_PAYLOAD};
pub const V1_HEADER_SIZE: usize = 14;
pub const V2_HEADER_SIZE: usize = 16;
pub const ED25519_SIG_SIZE: usize = 64;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {{
{ft_variants}
}}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Intent {{
{intent_variants}
}}

/// V1 frame header (14 bytes, network byte order)
#[repr(C, packed)]
pub struct FrameV1Header {{
    pub version: u8,
    pub frame_type: u8,
    pub agent_id: u32,
    pub timestamp: u32,
    pub confidence: u8,
    pub intent: u8,
    pub payload_len: i16,
}}

/// V2 frame header (16 bytes, network byte order)
#[repr(C, packed)]
pub struct FrameV2Header {{
    pub version: u8,
    pub frame_type: u8,
    pub agent_id: u32,
    pub timestamp: u32,
    pub confidence: u8,
    pub intent: u8,
    pub payload_len: i16,
    pub sig_len: u16,
}}

/// Decoded frame
#[derive(Debug)]
pub struct Frame {{
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
}}

impl Frame {{
    /// Decode confidence byte to float
    pub fn decode_confidence(raw: u8) -> f32 {{
        raw as f32 / 255.0
    }}

    /// Encode confidence float to byte
    pub fn encode_confidence(conf: f32) -> u8 {{
        (conf.clamp(0.0, 1.0) * 255.0) as u8
    }}
}}
'''


# ── Format Registry ───────────────────────────────────────────────

FORMATS = {
    "protobuf": ("thoughtwire.proto", generate_protobuf),
    "proto": ("thoughtwire.proto", generate_protobuf),
    "flatbuffers": ("thoughtwire.fbs", generate_flatbuffers),
    "fbs": ("thoughtwire.fbs", generate_flatbuffers),
    "json": ("thoughtwire.schema.json", generate_json_schema),
    "jsonschema": ("thoughtwire.schema.json", generate_json_schema),
    "c": ("thoughtwire.h", generate_c_header),
    "rust": ("thoughtwire.rs", generate_rust),
}


def generate(fmt: str) -> tuple:
    """Generate schema in given format. Returns (filename, content_string)."""
    if fmt not in FORMATS:
        raise ValueError(f"Unknown format: {fmt}. Available: {', '.join(sorted(set(f for f, _ in FORMATS.values())))}")
    
    filename, gen_fn = FORMATS[fmt]
    content = gen_fn()
    
    if isinstance(content, dict):
        return filename, json.dumps(content, indent=2)
    return filename, content
