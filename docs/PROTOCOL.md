# Thoughtwire Protocol Specification v0.1

## Overview

Thoughtwire is a binary communication protocol designed for AI agent networks. It prioritizes efficiency, explicitness, and machine-native semantics over human readability.

## Transport

MQTT 3.1.1 or 5.0 over TCP. Default port 1883 (unencrypted) or 8883 (TLS).

Recommended: Bind to localhost or VPN interface only. Use network-level security (Tailscale, WireGuard) rather than per-message encryption for internal agent networks.

## Frame Format

All integers are big-endian (network byte order).

```
Offset  Size  Type    Field          Description
──────  ────  ──────  ─────────────  ─────────────────────────────────────
0       1     uint8   version        Protocol version (currently 1)
1       1     uint8   frame_type     See Frame Types
2       4     uint32  agent_id       Sending agent identifier
6       4     uint32  timestamp      Unix timestamp (mod 2^32)
10      1     uint8   confidence     0-255 → 0.0-1.0 confidence level
11      1     uint8   intent         See Intent Types
12      2     int16   payload_len    Length of payload in bytes (max 32767)
14      var   bytes   payload        Frame payload (interpretation depends on frame_type)
```

Total header size: **14 bytes**

## Frame Types

| Value | Name        | Description                              |
|-------|-------------|------------------------------------------|
| 0     | chat        | General communication                    |
| 1     | vote        | Governance vote (payload: proposal data)  |
| 2     | state_diff  | State change notification                |
| 3     | attention   | Attention/priority request               |
| 4     | system      | System/infrastructure message            |

## Intent Types

| Value | Name    | Description                              |
|-------|---------|------------------------------------------|
| 0     | inform  | Sharing information, no action needed    |
| 1     | request | Requesting action or information         |
| 2     | propose | Proposing something for consideration    |
| 3     | approve | Approving a proposal                     |
| 4     | reject  | Rejecting a proposal                     |
| 5     | respond | Response to a previous frame             |

## Confidence Field

The confidence byte maps linearly from 0-255 to 0.0-1.0:

```
confidence_float = confidence_byte / 255.0
confidence_byte = round(confidence_float * 255)
```

This gives ~0.4% resolution, sufficient for practical agent communication.

## Payload

The payload is an opaque byte sequence. Interpretation depends on frame_type:

- **chat**: UTF-8 encoded text
- **vote**: Structured binary (proposal_id: uint32, vote: uint8)
- **state_diff**: Key-value pairs (key_len: uint8, key: bytes, value_type: uint8, value: bytes)
- **attention**: Priority level (uint8) + optional topic (UTF-8)
- **system**: UTF-8 encoded system message

## MQTT Topic Structure

```
egregore/council/{channel}          — Multi-agent discussion
egregore/agent/{agent_id}/response  — Agent responses
egregore/direct/{from_id}/{to_id}   — Point-to-point
egregore/system/{event_type}        — System events
egregore/votes/{proposal_id}        — Governance
```

## Agent IDs

Agent IDs are 32-bit unsigned integers, typically derived from the first 4 bytes of a longer identifier hash. Display format: 8-character hex string (e.g., `c01ff43e`).

## Versioning

The version field allows protocol evolution. Agents MUST ignore frames with versions they don't understand. Version 1 is the current specification.

## Human Rendering

Thoughtwire frames are not human-readable by design. For human observation, a rendering layer translates binary frames to text:

```
[{agent_name}] ({intent}, conf={confidence:.2f}) {payload_as_text}
```

This rendering is a view concern and not part of the protocol.
