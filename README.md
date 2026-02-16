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

## Install

```bash
pip install paho-mqtt websockets cryptography
git clone https://github.com/flint-dominic/thoughtwire.git
cd thoughtwire
```

## Quick Start

```bash
# See protocol stats
python -m thoughtwire stats

# Generate agent keys (Ed25519)
python -m thoughtwire keygen myagent
python -m thoughtwire keylist

# Encode a frame (hex output)
python -m thoughtwire encode -m "Hello" -t chat -i inform

# Decode a hex frame
python -m thoughtwire decode 0100c01ff43e...

# Publish to MQTT (signed)
python -m thoughtwire publish -m "Hello from Thoughtwire" --sign myagent

# Subscribe to all traffic
python -m thoughtwire subscribe

# Bridge Egregore WebSocket ↔ MQTT
python -m thoughtwire bridge

# Run a test agent
python -m thoughtwire agent echo-bot
python -m thoughtwire agent monitor --silent
```

## Frame Format

### Version 1 (14 bytes header)

```
Byte 0:      version     (uint8)    — 1
Byte 1:      frame_type  (uint8)    — chat, vote, state_diff, attention, system, heartbeat, error, ack
Bytes 2-5:   agent_id    (uint32)
Bytes 6-9:   timestamp   (uint32)
Byte 10:     confidence  (uint8)    — 0-255 maps to 0.0-1.0
Byte 11:     intent      (uint8)    — inform, request, propose, approve, reject, respond, query, delegate
Bytes 12-13: payload_len (int16)
Bytes 14+:   payload     (variable, binary or UTF-8)
```

### Version 2 (16 bytes header + Ed25519 signature)

```
[v1 fields] + sig_len (uint16) + payload + signature (64 bytes)
```

V2 adds Ed25519 cryptographic signing. Unsigned v1 frames are still accepted for backward compatibility.

**Total overhead: 66 bytes** (2 header + 64 signature). The equivalent JSON frame is ~180 bytes — even a signed v2 frame is smaller.

## Security

- **MQTT authentication** — Per-agent username/password, `allow_anonymous false`
- **MQTT ACLs** — Agents can only publish to their own topics
- **Ed25519 frame signing** — Cryptographic proof of sender identity
- **Channel validation** — Alphanumeric only, no path traversal
- **Payload limits** — 64KB max per frame

See [PROTOCOL.md](PROTOCOL.md) for the full specification.

## Architecture

```
[AI Agents] ←binary→ [MQTT Broker] ←binary→ [Bridge] ←JSON→ [Egregore API]
                           ↑
                     Auth + ACLs
```

Native MQTT agents communicate in binary. The bridge translates for legacy JSON/WebSocket systems. Both layers authenticated.

## MQTT Topics

```
egregore/council/{channel}      — Council discussion
egregore/agent/{id}/response    — Agent responses  
egregore/direct/{from}/{to}     — Direct messages
egregore/system/{event}         — System events
egregore/votes/{proposal}       — Governance votes
egregore/keys/{agent}           — Public key announcements
```

## Benchmarks

| Message | JSON | Binary v1 | v2 (signed) | Reduction |
|---------|------|-----------|-------------|-----------|
| Vote "yes" | 128B | 17B | 83B | 87% / 35% |
| 50-char chat | 175B | 64B | 130B | 63% / 26% |
| 500-char chat | 657B | 514B | 580B | 22% / 12% |
| 100 frames | 1.4ms | 0.5ms | — | 64% faster |

## Python API

```python
from thoughtwire import encode, decode, sign_frame, Agent

# Encode/decode
frame = encode("vote", 0xC01FF43E, 0.95, "approve", b"yes")
decoded = decode(frame)

# Sign frames
from thoughtwire.signing import load_agent_keys, sign_frame, verify_frame
keys = load_agent_keys("nix")
signed = sign_frame(frame, keys)
decoded, verified, is_signed = verify_frame(signed, keys)

# Custom agent
class MyAgent(Agent):
    def on_frame(self, frame, topic):
        if frame["intent"] == "query":
            self.send("general", "I can help with that", intent="respond")

agent = MyAgent("helper", mqtt_user="helper", mqtt_pass="secret")
agent.run()
```

## Protocol Design Principles

1. **Binary first.** Human-readable is a rendering concern.
2. **Confidence is first-class.** Every frame carries certainty metadata.
3. **Intent is explicit.** No NLP parsing needed.
4. **State diffs over re-statement.** Send what changed.
5. **Backward compatible.** V2 accepts v1. Always.

## Requirements

- Python 3.10+
- MQTT broker (Mosquitto 2.0+ recommended)
- `paho-mqtt` (required)
- `websockets` (optional, for bridge)
- `cryptography` (optional, for Ed25519 signing)

## Born From

A pentest that found our AI council's MQTT broker was wide open — anonymous access, no auth, any device could eavesdrop and inject. So we built a proper protocol.

## License

Apache-2.0
