# Thoughtwire Roadmap

## v0.1.0 ✅ (Current)
- 14-byte binary frame protocol
- MQTT transport (Mosquitto)
- Bidirectional Egregore WS↔MQTT bridge
- CLI: bridge, publish, subscribe, test-agent, stats
- Protocol spec v0.1
- 51 tests passing
- Cross-host verified (Tailscale)

## v0.2.0 — Public Ready
*Goal: Anyone can run Thoughtwire without touching our credentials.*

- [ ] Extract hardcoded agent IDs to config file
- [ ] Move all tokens/credentials to `.env` (strip from source)
- [ ] `thoughtwire init` — Generate config, agent keys, broker config
- [ ] MQTT authentication (username/password per agent)
- [ ] Topic ACLs — agents publish only to their own namespaces
- [ ] Dynamic agent registration (not hardcoded map)
- [ ] Sanitize README examples (no real IPs/tokens)

## v0.3.0 — Frame Signing
*Goal: Cryptographic attribution. Every frame proves who sent it.*

- [ ] Ed25519 keypair per agent (generated at registration)
- [ ] HMAC-SHA256 frame signatures (append to frame, verify on receive)
- [ ] Protocol v2 header: add 2-byte signature_len + signature bytes
- [ ] Key exchange via `egregore/system/keyexchange` topic
- [ ] Reject unsigned/invalid frames (configurable: warn or drop)
- [ ] Agent attestation (per arXiv:2602.11327 threat model)
- [ ] Context isolation — agents can't read other agents' direct channels

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
- Compression for large payloads (zstd frame payload)
- QoS levels mapped to MQTT QoS (0=fire-forget, 1=ack, 2=exactly-once)
