#!/usr/bin/env python3
"""Tests for Thoughtwire protocol — frame encoding/decoding, MQTT delivery, bridge logic."""

import json
import struct
import time
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from bridge import (
    encode_frame, decode_frame, json_to_binary, binary_to_json,
    FRAME_HEADER, FRAME_TYPES, INTENTS, AGENTS
)

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name} — {detail}")
        failed += 1


# ── Frame Format Tests ──────────────────────────────────────────

print("\n🔬 Frame Format")

test("Header is 14 bytes", FRAME_HEADER.size == 14, f"got {FRAME_HEADER.size}")

frame = encode_frame("chat", 0xDEADBEEF, 0.5, "inform", b"hello")
test("Encode returns bytes", isinstance(frame, bytes))
test("Encode length = header + payload", len(frame) == 14 + 5, f"got {len(frame)}")

frame_no_payload = encode_frame("vote", 0x12345678, 1.0, "approve")
test("Empty payload = header only", len(frame_no_payload) == 14)


# ── Encode/Decode Roundtrip ─────────────────────────────────────

print("\n🔬 Encode/Decode Roundtrip")

for ftype in ["chat", "vote", "state_diff", "attention", "system"]:
    f = encode_frame(ftype, 0xAABBCCDD, 0.73, "propose", b"test payload")
    d = decode_frame(f)
    test(f"Roundtrip frame_type={ftype}", d["frame_type"] == ftype, f"got {d['frame_type']}")

for intent in ["inform", "request", "propose", "approve", "reject", "respond"]:
    f = encode_frame("chat", 0x11111111, 0.5, intent, b"x")
    d = decode_frame(f)
    test(f"Roundtrip intent={intent}", d["intent"] == intent, f"got {d['intent']}")


# ── Confidence Precision ────────────────────────────────────────

print("\n🔬 Confidence Precision")

for conf in [0.0, 0.25, 0.5, 0.73, 0.99, 1.0]:
    f = encode_frame("chat", 0, conf, "inform")
    d = decode_frame(f)
    # uint8 gives ~0.4% precision
    test(f"Confidence {conf} roundtrip", abs(d["confidence"] - conf) < 0.01,
         f"got {d['confidence']:.4f}")


# ── Agent ID Roundtrip ──────────────────────────────────────────

print("\n🔬 Agent IDs")

for name, aid in AGENTS.items():
    f = encode_frame("chat", aid, 0.5, "inform")
    d = decode_frame(f)
    test(f"Agent {name} ID roundtrip", d["agent_id"] == aid,
         f"expected {aid:#x}, got {d['agent_id']:#x}")


# ── Payload Tests ───────────────────────────────────────────────

print("\n🔬 Payloads")

# UTF-8 text
text = "Hello from Thoughtwire! 🌀⚡"
f = encode_frame("chat", 0, 1.0, "inform", text.encode("utf-8"))
d = decode_frame(f)
test("UTF-8 payload roundtrip", d["payload_text"] == text, f"got {d['payload_text']}")

# Binary payload
binary_data = struct.pack("!HfI", 42, 3.14, 1000000)
f = encode_frame("state_diff", 0, 0.9, "inform", binary_data)
d = decode_frame(f)
unpacked = struct.unpack("!HfI", d["payload"])
test("Binary payload roundtrip", unpacked[0] == 42 and abs(unpacked[1] - 3.14) < 0.001 and unpacked[2] == 1000000,
     f"got {unpacked}")

# Empty payload
f = encode_frame("attention", 0, 0.95, "request")
d = decode_frame(f)
test("Empty payload", d["payload"] == b"" and d["payload_text"] == "")

# Max payload (32767 bytes)
big = b"X" * 32767
f = encode_frame("chat", 0, 0.5, "inform", big)
d = decode_frame(f)
test("Max payload (32767 bytes)", len(d["payload"]) == 32767)


# ── Edge Cases ──────────────────────────────────────────────────

print("\n🔬 Edge Cases")

# Too-short data
test("Decode <14 bytes returns None", decode_frame(b"short") is None)
test("Decode empty returns None", decode_frame(b"") is None)

# Zero agent ID
f = encode_frame("chat", 0, 0.0, "inform", b"zero")
d = decode_frame(f)
test("Zero agent ID", d["agent_id"] == 0)
test("Zero confidence", d["confidence"] == 0.0)

# Max agent ID
f = encode_frame("chat", 0xFFFFFFFF, 1.0, "reject")
d = decode_frame(f)
test("Max agent ID (0xFFFFFFFF)", d["agent_id"] == 0xFFFFFFFF)


# ── JSON Conversion ─────────────────────────────────────────────

print("\n🔬 JSON Conversion")

egregore_frame = {
    "agent_id": "c01ff43edb829606",
    "channel": "general",
    "frame_type": "facade.chat",
    "payload": {"text": "Council topic: testing"}
}

binary = json_to_binary(egregore_frame)
test("json_to_binary produces bytes", isinstance(binary, bytes))
test("json_to_binary header present", len(binary) >= 14)

decoded = decode_frame(binary)
test("json_to_binary text preserved", decoded["payload_text"] == "Council topic: testing")
test("json_to_binary agent ID extracted", decoded["agent_id"] == 0xc01ff43e)

back_to_json = binary_to_json(decoded, "general")
test("binary_to_json has channel", back_to_json["channel"] == "general")
test("binary_to_json has text", back_to_json["payload"]["text"] == "Council topic: testing")


# ── Size Comparison ─────────────────────────────────────────────

print("\n🔬 Size Comparison")

test_messages = [
    ("short", "yes"),
    ("medium", "I approve the proposal for adding GLM-5 to the council"),
    ("long", "A" * 500),
]

for label, text in test_messages:
    json_size = len(json.dumps({"agent": "c01ff43e", "confidence": 0.87, 
                                 "intent": "approve", "text": text}).encode())
    binary_size = len(encode_frame("vote", 0xc01ff43e, 0.87, "approve", 
                                    text.encode("utf-8")))
    ratio = binary_size / json_size
    test(f"Binary smaller ({label}: {binary_size}B vs {json_size}B JSON, {ratio:.0%})",
         binary_size <= json_size, f"binary={binary_size}, json={json_size}")


# ── MQTT Live Tests ─────────────────────────────────────────────

print("\n🔬 MQTT Live Tests")

try:
    import paho.mqtt.client as mqtt
    
    # Test 1: Publish and receive a binary frame
    received = []
    
    def on_msg(client, userdata, msg):
        received.append(msg)
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="test-runner")
    client.on_message = on_msg
    client.connect("127.0.0.1", 1883)
    client.subscribe("egregore/test/protocol/#")
    client.loop_start()
    time.sleep(0.5)
    
    # Send binary frame
    test_frame = encode_frame("chat", 0xAAAAAAAA, 
                               0.77, "propose", b"test message")
    client.publish("egregore/test/protocol/roundtrip", test_frame)
    time.sleep(1)
    
    test("MQTT publish+receive", len(received) == 1, f"received {len(received)}")
    
    if received:
        decoded = decode_frame(received[0].payload)
        test("MQTT frame integrity", decoded["payload_text"] == "test message",
             f"got {decoded['payload_text']}")
        test("MQTT confidence preserved", abs(decoded["confidence"] - 0.77) < 0.01)
        test("MQTT intent preserved", decoded["intent"] == "propose")
    
    # Test 2: Burst delivery
    received2 = []
    client2 = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="test-burst")
    client2.on_message = lambda c, u, m: received2.append(m)
    client2.connect("127.0.0.1", 1883)
    client2.subscribe("egregore/test/burst/#")
    client2.loop_start()
    time.sleep(0.5)
    
    N = 50
    for i in range(N):
        f = encode_frame("chat", i, i/N, "inform", f"burst-{i}".encode())
        client2.publish(f"egregore/test/burst/{i}", f)
    
    time.sleep(2)
    test(f"MQTT burst delivery ({N} frames)", len(received2) == N,
         f"received {len(received2)}/{N}")
    
    # Verify ordering
    if len(received2) == N:
        texts = [decode_frame(m.payload)["payload_text"] for m in received2]
        expected = [f"burst-{i}" for i in range(N)]
        test("MQTT burst ordering", texts == expected)
    
    client.loop_stop()
    client.disconnect()
    client2.loop_stop()
    client2.disconnect()

except ImportError:
    test("MQTT tests (paho-mqtt not installed)", False, "pip install paho-mqtt")
except ConnectionRefusedError:
    test("MQTT tests (broker not running)", False, "start mosquitto")


# ── Cross-host Test ─────────────────────────────────────────────

print("\n🔬 Cross-host Test (yogsothoth → cthonian)")

import subprocess

try:
    received_cross = []
    client3 = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="test-crosshost")
    client3.on_message = lambda c, u, m: received_cross.append(m)
    client3.connect("127.0.0.1", 1883)
    client3.subscribe("egregore/test/crosshost/#")
    client3.loop_start()
    time.sleep(0.5)
    
    result = subprocess.run(
        ["ssh", "yogsothoth", "mosquitto_pub -h 100.125.228.90 -t egregore/test/crosshost/ping -m 'yogsothoth_alive'"],
        capture_output=True, timeout=10
    )
    time.sleep(2)
    
    test("Cross-host delivery", len(received_cross) == 1, f"received {len(received_cross)}")
    if received_cross:
        test("Cross-host payload", received_cross[0].payload == b"yogsothoth_alive")
    
    client3.loop_stop()
    client3.disconnect()

except Exception as e:
    test("Cross-host test", False, str(e))


# ── Summary ─────────────────────────────────────────────────────

print(f"\n{'='*50}")
print(f"  Results: {passed} passed, {failed} failed")
print(f"{'='*50}")

sys.exit(1 if failed else 0)
