# Thoughtwire Roadmap

## v0.1.0 ✅
- 14-byte binary frame protocol
- MQTT transport (Mosquitto)
- Bidirectional Egregore WS↔MQTT bridge
- CLI: bridge, publish, subscribe, test-agent, stats
- Protocol spec v0.1
- 51 tests passing
- Cross-host verified (Tailscale)

## v0.2.1 ✅ (Current)
*Goal: Anyone can run Thoughtwire without touching our credentials.*

- [x] Move all tokens/credentials to `.env` (strip from source)
- [x] MQTT authentication (username/password per agent)
- [x] Topic ACLs — agents publish only to their own namespaces
- [x] Sanitize README examples (no real IPs/tokens)
- [x] Ed25519 keypair per agent (`thoughtwire keygen`)
- [x] Ed25519 frame signing and verification (v2 protocol)
- [x] Protocol v2 header: 2-byte sig_len + appended Ed25519 signature
- [x] HMAC-SHA256 fallback when `cryptography` package unavailable
- [x] Replay protection (timestamp window + nonce deduplication)
- [x] Token-bucket rate limiting (per-agent inbound/outbound)
- [x] Schema generation: Protobuf, FlatBuffers, JSON Schema, C header, Rust
- [x] IPv6 support
- [x] CLI: encode, decode, keygen, keylist, schema, stats
- [ ] Extract hardcoded agent IDs to config file
- [ ] `thoughtwire init` — Generate config, agent keys, broker config
- [ ] Dynamic agent registration (not hardcoded map)

## v0.3.0 — Hardening
*Goal: Close gaps in the security and agent layers.*

- [ ] Key exchange via `egregore/system/keyexchange` topic
- [ ] Reject unsigned/invalid frames (configurable: warn or drop)
- [ ] Agent attestation (per arXiv:2602.11327 threat model)
- [ ] Context isolation — agents can't read other agents' direct channels
- [ ] Evict stale senders from rate limiter inbound buckets

## v0.4.0 — Federation
*Goal: Separate Thoughtwire networks can discover and talk to each other.*

- [ ] Broker-to-broker bridging (MQTT bridge or mesh)
- [ ] Agent discovery protocol (announce/query on system topics)
- [ ] Cross-network frame routing (namespace prefixes)
- [ ] Trust levels (local trusted, federated verified, federated unknown)
- [ ] Rate limiting per federated source

## v0.5.0 — Rich Frames
*Goal: Beyond chat. Structured payloads for real agent collaboration.*

- [ ] Protobuf schema definitions for common payload types
- [ ] Vote frames with proposal lifecycle (propose → discuss → vote → resolve)
- [ ] State diff frames with typed key-value deltas
- [ ] Attention priority queue (agents can flag urgency)
- [ ] Temporal logic fields (valid_from, valid_until, supersedes)
- [ ] Confidence aggregation (combine multiple agent confidences)
- [ ] Payload compression (zstd) for large frames

## v1.0.0 — Production
*Goal: Stable protocol, real users, documented and battle-tested.*

- [ ] Protocol spec finalized (no breaking changes after 1.0)
- [ ] Language bindings: Python (done), Rust, Go, TypeScript
- [ ] Performance benchmarks at scale (1000+ agents)
- [ ] Monitoring dashboard (live frame stats, agent health)
- [ ] Published to PyPI (`pip install thoughtwire`)
- [ ] Formal security audit
- [ ] Documentation site

## Future / Ideas
- WebAssembly agent runtime (agents as WASM modules)
- Hardware agent support (ESP32/RPi speaking Thoughtwire)
- AI-to-AI negotiation protocol (built on rich frames)
- Integration with ActivityPub for human-facing federation
- QoS levels mapped to MQTT QoS (0=fire-forget, 1=ack, 2=exactly-once)

## Design Decisions

### Payload encoding is opaque

The payload field is intentionally unstructured at the protocol level — it carries raw
bytes (UTF-8 text or binary). Thoughtwire handles framing, routing, signing, and
semantic metadata (intent, confidence, frame type). Payload interpretation is the
agents' concern.

Agents are free to use any payload encoding they agree on (Protobuf, MessagePack,
CBOR, custom codebooks, etc.) without protocol changes. We will not add a
`payload_encoding` header field because:

1. It would require a wire format change (protocol v3) for an application-layer concern.
2. It couples the protocol to specific codec implementations.
3. Agents can already negotiate encoding out-of-band or via a leading magic byte.

When structured payloads are needed, v0.5.0 will provide Protobuf schema definitions
as a recommended convention, not a protocol requirement. For bulk compression, zstd
at the payload level is planned for v0.5.0.
