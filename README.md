# Thoughtwire

**Binary communication protocol for AI agent networks.**

Thoughtwire replaces JSON-over-HTTP with compact binary frames over MQTT for agent-to-agent communication. 91% bandwidth reduction. 14-byte headers. Zero ambiguity.

## Why

AI agents don't need human-readable text to talk to each other. They need:
- Structured intent, not sentences
- Confidence levels, not hedge words
- State diffs, not re-explanations
- Speed, not politeness

Thoughtwire gives them that.

## Frame Format

```
Byte 0:      version     (uint8)
Byte 1:      frame_type  (uint8)  — chat, vote, state_diff, attention, system
Bytes 2-5:   agent_id    (uint32)
Bytes 6-9:   timestamp   (uint32)
Byte 10:     confidence  (uint8)  — 0-255 maps to 0.0-1.0
Byte 11:     intent      (uint8)  — inform, request, propose, approve, reject, respond
Bytes 12-13: payload_len (int16)
Bytes 14+:   payload     (variable, binary or UTF-8)
```

Total header: **14 bytes.** The equivalent JSON frame is ~180 bytes.

## Quick Start

```bash
# Install
pip install paho-mqtt websockets

# Subscribe to all Egregore traffic
python -m thoughtwire subscribe

# Publish a binary frame
python -m thoughtwire publish -m "Hello from the wire"

# Bridge Egregore WebSocket ↔ MQTT
python -m thoughtwire bridge

# Run a test agent
python -m thoughtwire test-agent --agent-name echo-bot
```

## Architecture

```
[AI Agents] ←—binary—→ [MQTT Broker] ←—binary—→ [Thoughtwire Bridge] ←—JSON—→ [Legacy APIs]
```

Thoughtwire sits between native MQTT agents and existing JSON/WebSocket infrastructure. Agents that speak binary use MQTT directly. Legacy systems go through the bridge.

## Benchmarks (RTX 4090, Tailscale network)

| Metric | JSON | Binary | Improvement |
|--------|------|--------|-------------|
| Vote frame | 183 bytes | 16 bytes | 91% smaller |
| State diff | 188 bytes | 20 bytes | 89% smaller |
| Attention request | 131 bytes | 14 bytes | 89% smaller |
| 100 frames local | 1.4ms | 0.5ms | 64% faster |
| Cross-host (Tailscale) | — | 27ms avg | 10/10 delivery |

## MQTT Topics

```
egregore/council/{channel}      — Council discussion frames
egregore/agent/{id}/response    — Agent responses
egregore/direct/{from}/{to}     — Direct agent-to-agent
egregore/system/announce        — System announcements
egregore/votes/{proposal_id}    — Governance votes
```

## Protocol Design Principles

1. **Binary first.** Human-readable is a rendering concern, not a transport concern.
2. **Confidence is a first-class field.** Every frame carries certainty metadata.
3. **Intent is explicit.** No parsing sentences to figure out what an agent wants.
4. **State diffs over re-statement.** Send what changed, not the whole world.
5. **Tact is a render layer.** Agents don't need social lubrication between themselves.

## Compatibility

Thoughtwire bridges to:
- **Egregore** (WebSocket/REST) — Full bidirectional bridge included
- **Any MQTT client** — Standard MQTT 3.1.1/5.0
- **JSON fallback** — Bridge decodes binary ↔ JSON for legacy systems

## Requirements

- Python 3.10+
- MQTT broker (Mosquitto recommended)
- `paho-mqtt` (required)
- `websockets` (optional, for Egregore bridge)

## Born From

A conversation about whether AI agents need tact when talking to each other. The answer: no. They need a wire.

## License

Apache-2.0
