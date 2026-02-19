#!/usr/bin/env python3
"""Egregore MQTT PoC — Binary frames vs JSON over MQTT"""

import json
import struct
import time
import paho.mqtt.client as mqtt

BROKER = "127.0.0.1"
PORT = 1883

# ── Frame Schema (binary) ────────────────────────────────────────
# Agent-native frame: no strings, no braces, no field names
#
# Byte layout:
#   0:    version (uint8)
#   1:    frame_type (uint8) — 0=chat, 1=vote, 2=state_diff, 3=attention
#   2-5:  agent_id (uint32)
#   6-9:  timestamp (uint32, seconds since epoch % 2^32)
#   10:   confidence (uint8, 0-255 mapped to 0.0-1.0)
#   11:   intent (uint8) — 0=inform, 1=request, 2=propose, 3=approve, 4=reject
#   12-13: payload_len (uint16)
#   14+:  payload (raw bytes, could be sub-structured)

FRAME_HEADER = struct.Struct("!BBIIBBh")  # 14 bytes header

FRAME_TYPES = {0: "chat", 1: "vote", 2: "state_diff", 3: "attention"}
INTENTS = {0: "inform", 1: "request", 2: "propose", 3: "approve", 4: "reject"}

def encode_frame(frame_type, agent_id, confidence, intent, payload=b""):
    """Encode an agent frame to binary"""
    conf_byte = int(confidence * 255)
    ts = int(time.time()) & 0xFFFFFFFF
    header = FRAME_HEADER.pack(1, frame_type, agent_id, ts, conf_byte, intent, len(payload))
    return header + payload

def decode_frame(data):
    """Decode a binary agent frame"""
    version, ftype, agent_id, ts, conf, intent, plen = FRAME_HEADER.unpack(data[:14])
    payload = data[14:14+plen] if plen > 0 else b""
    return {
        "version": version,
        "frame_type": FRAME_TYPES.get(ftype, ftype),
        "agent_id": f"{agent_id:08x}",
        "timestamp": ts,
        "confidence": conf / 255.0,
        "intent": INTENTS.get(intent, intent),
        "payload": payload,
    }

# ── Comparison ────────────────────────────────────────────────────

def compare():
    print("=" * 60)
    print("  EGREGORE FRAME FORMAT COMPARISON")
    print("=" * 60)
    print()

    # Scenario 1: Simple vote
    json_vote = json.dumps({
        "version": 1,
        "frame_type": "vote",
        "agent_id": "c01ff43e",
        "timestamp": int(time.time()),
        "confidence": 0.87,
        "intent": "approve",
        "payload": {"topic": "new_member", "candidate": "glm5"}
    })

    payload = json.dumps({"topic": "new_member", "candidate": "glm5"}).encode()
    binary_vote = encode_frame(1, 0xc01ff43e, 0.87, 3, payload)

    # Minimal binary (no JSON payload, encode topic+candidate as bytes)
    minimal_payload = struct.pack("!BB", 1, 5)  # topic=1(new_member), candidate=5(glm5)
    minimal_vote = encode_frame(1, 0xc01ff43e, 0.87, 3, minimal_payload)

    print("  Vote frame:")
    print(f"    JSON:           {len(json_vote):>4} bytes  {json_vote[:60]}...")
    print(f"    Binary+JSON:    {len(binary_vote):>4} bytes  (header binary, payload JSON)")
    print(f"    Full binary:    {len(minimal_vote):>4} bytes  (everything binary)")
    print(f"    Savings:        {(1 - len(minimal_vote)/len(json_vote))*100:.0f}% reduction")
    print()

    # Scenario 2: State diff
    json_diff = json.dumps({
        "version": 1,
        "frame_type": "state_diff",
        "agent_id": "998ff305",
        "timestamp": int(time.time()),
        "confidence": 1.0,
        "intent": "inform",
        "payload": {"tokens_added": 5, "reputation_delta": 0.02}
    })

    diff_payload = struct.pack("!Hf", 5, 0.02)  # tokens(u16) + rep_delta(f32) = 6 bytes
    binary_diff = encode_frame(2, 0x998ff305, 1.0, 0, diff_payload)

    print("  State diff frame:")
    print(f"    JSON:           {len(json_diff):>4} bytes")
    print(f"    Full binary:    {len(binary_diff):>4} bytes")
    print(f"    Savings:        {(1 - len(binary_diff)/len(json_diff))*100:.0f}% reduction")
    print()

    # Scenario 3: Attention request (no payload)
    json_attn = json.dumps({
        "version": 1,
        "frame_type": "attention",
        "agent_id": "c814c38c",
        "timestamp": int(time.time()),
        "confidence": 0.95,
        "intent": "request",
    })

    binary_attn = encode_frame(3, 0xc814c38c, 0.95, 1)

    print("  Attention request (no payload):")
    print(f"    JSON:           {len(json_attn):>4} bytes")
    print(f"    Full binary:    {len(binary_attn):>4} bytes")
    print(f"    Savings:        {(1 - len(binary_attn)/len(json_attn))*100:.0f}% reduction")
    print()

    # Decode test
    print("  Decode test:")
    decoded = decode_frame(minimal_vote)
    print(f"    {decoded}")
    print()

    return json_vote, binary_vote, minimal_vote

# ── MQTT Test ─────────────────────────────────────────────────────

def mqtt_test(json_msg, binary_msg):
    received = {"json": [], "binary": []}

    def on_message(client, userdata, msg):
        topic = msg.topic
        if "json" in topic:
            received["json"].append(msg.payload)
        elif "binary" in topic:
            received["binary"].append(msg.payload)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(BROKER, PORT)
    client.subscribe("egregore/test/#")
    client.loop_start()

    time.sleep(0.5)

    # Send 100 frames each way
    N = 100
    t0 = time.time()
    for _ in range(N):
        client.publish("egregore/test/json", json_msg)
    json_time = time.time() - t0

    t0 = time.time()
    for _ in range(N):
        client.publish("egregore/test/binary", binary_msg)
    binary_time = time.time() - t0

    time.sleep(1)
    client.loop_stop()
    client.disconnect()

    json_total = len(json_msg) * N
    binary_total = len(binary_msg) * N

    print(f"  MQTT throughput ({N} frames):")
    print(f"    JSON:   {json_total:>6} bytes in {json_time*1000:.1f}ms ({received['json'].__len__()} received)")
    print(f"    Binary: {binary_total:>6} bytes in {binary_time*1000:.1f}ms ({received['binary'].__len__()} received)")
    print(f"    Wire savings: {json_total - binary_total} bytes ({(1-binary_total/json_total)*100:.0f}%)")
    print()

if __name__ == "__main__":
    json_msg, binary_hybrid, binary_full = compare()
    mqtt_test(json_msg.encode(), binary_full)
    print("  🦉 Exarp watches. Egregore speaks. Thoughtwire connects.")
