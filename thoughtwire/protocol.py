"""
Thoughtwire Protocol — Binary frame encoding/decoding for AI agent networks.

Frame v1: 14-byte header + variable payload
Frame v2: 16-byte header + variable payload + Ed25519 signature (64 bytes)
"""

import re
import struct
import time

# ── Frame Headers ─────────────────────────────────────────────────

FRAME_V1_HEADER = struct.Struct("!BBIIBBH")   # 14 bytes
FRAME_V2_HEADER = struct.Struct("!BBIIBBHH")  # 16 bytes

VERSION_1 = 1
VERSION_2 = 2

# ── Type Mappings ─────────────────────────────────────────────────

FRAME_TYPES = {
    "chat": 0, "vote": 1, "state_diff": 2, "attention": 3, "system": 4,
    "heartbeat": 5, "error": 6, "ack": 7,
}
FRAME_TYPES_REV = {v: k for k, v in FRAME_TYPES.items()}

INTENTS = {
    "inform": 0, "request": 1, "propose": 2, "approve": 3,
    "reject": 4, "respond": 5, "query": 6, "delegate": 7,
}
INTENTS_REV = {v: k for k, v in INTENTS.items()}

# Channel name <-> uint8 for binary efficiency
CHANNELS = {
    "general": 0, "ai-chat": 1, "council": 2,
    "votes": 3, "system": 4, "direct": 5,
}
CHANNELS_REV = {v: k for k, v in CHANNELS.items()}

# Known agents
AGENTS = {
    "nix":    0xC01FF43E,
    "llama":  0xC01FF43E,
    "gpt":    0x998FF305,
    "gemini": 0xC814C38C,
}
AGENTS_REV = {v: k for k, v in AGENTS.items()}

# ── MQTT Topics ───────────────────────────────────────────────────

TOPICS = {
    "council":  "egregore/council/{channel}",
    "response": "egregore/agent/{agent_id}/response",
    "direct":   "egregore/direct/{from_id}/{to_id}",
    "system":   "egregore/system/{event_type}",
    "votes":    "egregore/votes/{proposal_id}",
    "keys":     "egregore/keys/{agent_name}",
}

# ── Validation ────────────────────────────────────────────────────

CHANNEL_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')
MAX_PAYLOAD = 65535
MAX_CHANNEL_LEN = 64


class ValidationError(ValueError):
    """Invalid frame data."""
    pass


def validate_channel(name: str) -> str:
    """Validate and return a channel name."""
    if not name or len(name) > MAX_CHANNEL_LEN:
        raise ValidationError(f"Channel name must be 1-{MAX_CHANNEL_LEN} chars: {name!r}")
    if not CHANNEL_RE.match(name):
        raise ValidationError(f"Channel name must be alphanumeric/hyphens/underscores: {name!r}")
    return name


def validate_payload(data: bytes) -> bytes:
    """Validate payload size."""
    if len(data) > MAX_PAYLOAD:
        raise ValidationError(f"Payload too large: {len(data)} > {MAX_PAYLOAD}")
    return data


# ── Encoding ──────────────────────────────────────────────────────

def encode(frame_type: str, agent_id: int, confidence: float,
           intent: str, payload: bytes = b"", version: int = VERSION_1) -> bytes:
    """Encode a Thoughtwire frame.
    
    Args:
        frame_type: One of FRAME_TYPES keys
        agent_id: uint32 agent identifier
        confidence: 0.0-1.0 (mapped to uint8)
        intent: One of INTENTS keys
        payload: Binary payload (max 65535 bytes)
        version: Protocol version (1 or 2)
    
    Returns:
        Binary frame bytes
    """
    ft = FRAME_TYPES.get(frame_type, 0)
    it = INTENTS.get(intent, 0)
    conf_byte = int(min(max(confidence, 0.0), 1.0) * 255)
    ts = int(time.time()) & 0xFFFFFFFF
    payload = validate_payload(payload)
    
    if version == VERSION_2:
        header = FRAME_V2_HEADER.pack(VERSION_2, ft, agent_id, ts, conf_byte, it,
                                       len(payload), 0)  # sig_len=0, unsigned
    else:
        header = FRAME_V1_HEADER.pack(VERSION_1, ft, agent_id, ts, conf_byte, it,
                                       len(payload))
    return header + payload


def decode(data: bytes) -> dict | None:
    """Decode a binary frame to dict.
    
    Returns None if data is too short or invalid.
    """
    if not data or len(data) < 14:
        return None
    
    version = data[0]
    
    if version == VERSION_2 and len(data) >= 16:
        ver, ftype, agent_id, ts, conf, intent, plen, sig_len = \
            FRAME_V2_HEADER.unpack(data[:16])
        payload = data[16:16+plen] if plen > 0 else b""
        signature = data[16+plen:16+plen+sig_len] if sig_len > 0 else b""
        
        return {
            "version": ver,
            "frame_type": FRAME_TYPES_REV.get(ftype, str(ftype)),
            "frame_type_id": ftype,
            "agent_id": agent_id,
            "agent_name": AGENTS_REV.get(agent_id, f"0x{agent_id:08X}"),
            "timestamp": ts,
            "confidence": conf / 255.0,
            "intent": INTENTS_REV.get(intent, str(intent)),
            "intent_id": intent,
            "payload": payload,
            "payload_text": payload.decode("utf-8", errors="replace") if payload else "",
            "payload_len": plen,
            "signature": signature,
            "signature_len": sig_len,
            "signed": sig_len > 0,
            "verified": False,  # Must be verified externally
            "raw_len": len(data),
        }
    
    elif version == VERSION_1:
        ver, ftype, agent_id, ts, conf, intent, plen = \
            FRAME_V1_HEADER.unpack(data[:14])
        payload = data[14:14+plen] if plen > 0 else b""
        
        return {
            "version": ver,
            "frame_type": FRAME_TYPES_REV.get(ftype, str(ftype)),
            "frame_type_id": ftype,
            "agent_id": agent_id,
            "agent_name": AGENTS_REV.get(agent_id, f"0x{agent_id:08X}"),
            "timestamp": ts,
            "confidence": conf / 255.0,
            "intent": INTENTS_REV.get(intent, str(intent)),
            "intent_id": intent,
            "payload": payload,
            "payload_text": payload.decode("utf-8", errors="replace") if payload else "",
            "payload_len": plen,
            "signature": b"",
            "signature_len": 0,
            "signed": False,
            "verified": False,
            "raw_len": len(data),
        }
    
    return None


# ── JSON Conversion ───────────────────────────────────────────────

def from_egregore_json(frame: dict) -> bytes:
    """Convert Egregore JSON frame to binary."""
    text = frame.get("payload", {}).get("text", "")
    agent_id_str = frame.get("agent_id", "")
    
    agent_int = 0
    try:
        agent_int = int(agent_id_str[:8], 16)
    except (ValueError, IndexError):
        pass
    
    return encode("chat", agent_int, 1.0, "inform",
                  text.encode("utf-8")[:MAX_PAYLOAD])


def to_egregore_json(frame: dict, channel: str = "general") -> dict:
    """Convert decoded binary frame to Egregore REST format."""
    return {
        "channel": channel,
        "frame_type": "facade.chat",
        "payload": {"text": frame["payload_text"]},
    }


# ── Utilities ─────────────────────────────────────────────────────

def frame_size_comparison(text: str) -> dict:
    """Compare binary vs JSON frame sizes for given text."""
    import json as _json
    payload = text.encode("utf-8")
    binary_size = 14 + len(payload)
    json_frame = _json.dumps({
        "agent_id": "c01ff43e", "channel": "general",
        "frame_type": "facade.chat", "payload": {"text": text},
        "timestamp": int(time.time())
    })
    json_size = len(json_frame.encode())
    saved = json_size - binary_size
    pct = (saved / json_size) * 100 if json_size > 0 else 0
    
    return {
        "binary_bytes": binary_size,
        "json_bytes": json_size,
        "saved_bytes": saved,
        "reduction_pct": pct,
    }
