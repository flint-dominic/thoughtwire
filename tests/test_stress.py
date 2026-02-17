#!/usr/bin/env python3
"""
Thoughtwire Stress Test Suite
Tests: protocol throughput, MQTT load, signing performance, concurrent agents
"""

import os
import sys
import time
import struct
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from thoughtwire.protocol import encode, decode, FRAME_TYPES, INTENTS, CHANNELS, VERSION_2
from thoughtwire.signing import generate_agent_keys, sign_frame, verify_frame, init_all_keys

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_USER = os.environ.get("MQTT_USER", "bridge")
MQTT_PASS = os.environ.get("MQTT_PASS", "thoughtwire_bridge_2026")

# ── Helpers ─────────────────────────────────────────────────────

def make_frame(text="Hello from stress test", agent_id=0xC01FF43E,
               frame_type="chat", intent="inform",
               confidence=0.95, version=VERSION_2):
    return encode(
        frame_type=frame_type,
        agent_id=agent_id,
        confidence=confidence,
        intent=intent,
        payload=text.encode("utf-8"),
        version=version,
    )


def fmt_rate(count, elapsed):
    rate = count / elapsed if elapsed > 0 else 0
    return f"{rate:,.0f}/s"


def fmt_size(nbytes):
    if nbytes > 1_000_000:
        return f"{nbytes/1_000_000:.1f}MB"
    return f"{nbytes/1_000:.1f}KB"


# ── Test 1: Encode/Decode Throughput ────────────────────────────

def test_encode_decode_throughput(n=100_000):
    print(f"\n{'='*60}")
    print(f"TEST 1: Encode/Decode Throughput ({n:,} frames)")
    print(f"{'='*60}")

    # Encode
    t0 = time.perf_counter()
    frames = []
    for i in range(n):
        f = make_frame(text=f"Stress test message #{i}", version=VERSION_2)
        frames.append(f)
    encode_time = time.perf_counter() - t0
    total_bytes = sum(len(f) for f in frames)

    print(f"  Encode: {n:,} frames in {encode_time:.3f}s → {fmt_rate(n, encode_time)}")
    print(f"  Total:  {fmt_size(total_bytes)} ({total_bytes/n:.0f} bytes/frame avg)")

    # Decode
    t0 = time.perf_counter()
    decoded = 0
    for f in frames:
        result = decode(f)
        if result:
            decoded += 1
    decode_time = time.perf_counter() - t0

    print(f"  Decode: {decoded:,} frames in {decode_time:.3f}s → {fmt_rate(decoded, decode_time)}")
    print(f"  Roundtrip: {fmt_rate(n, encode_time + decode_time)}")

    assert decoded == n, f"Only decoded {decoded}/{n}"
    return encode_time, decode_time


# ── Test 2: Signing Performance ─────────────────────────────────

def test_signing_performance(n=10_000):
    print(f"\n{'='*60}")
    print(f"TEST 2: Ed25519 Signing Performance ({n:,} frames)")
    print(f"{'='*60}")

    kp = generate_agent_keys("stresstest")
    frame_data = make_frame(text="Signing performance test frame")

    # Sign
    t0 = time.perf_counter()
    signed_frames = []
    for _ in range(n):
        signed = sign_frame(frame_data, kp)
        signed_frames.append(signed)
    sign_time = time.perf_counter() - t0

    print(f"  Sign:   {n:,} frames in {sign_time:.3f}s → {fmt_rate(n, sign_time)}")

    # Verify
    t0 = time.perf_counter()
    verified = 0
    for sf in signed_frames:
        result = verify_frame(sf, kp)
        if result and result[0]:
            verified += 1
    verify_time = time.perf_counter() - t0

    print(f"  Verify: {verified:,} frames in {verify_time:.3f}s → {fmt_rate(verified, verify_time)}")
    print(f"  Sign+Verify: {fmt_rate(n, sign_time + verify_time)}")

    assert verified == n, f"Only verified {verified}/{n}"
    return sign_time, verify_time


# ── Test 3: Payload Sizes ──────────────────────────────────────

def test_payload_sizes():
    print(f"\n{'='*60}")
    print(f"TEST 3: Payload Size Stress")
    print(f"{'='*60}")

    sizes = [1, 10, 100, 500, 1000, 5000, 10000, 30000]
    n_per = 1000

    for size in sizes:
        text = "X" * size
        t0 = time.perf_counter()
        for _ in range(n_per):
            f = make_frame(text=text)
            decode(f)
        elapsed = time.perf_counter() - t0
        print(f"  {size:>6} bytes: {n_per:,} roundtrips in {elapsed:.3f}s → {fmt_rate(n_per, elapsed)}")


# ── Test 4: Concurrent Encode/Decode ───────────────────────────

def test_concurrent_encoding(n_threads=8, n_per_thread=10_000):
    print(f"\n{'='*60}")
    print(f"TEST 4: Concurrent Encode/Decode ({n_threads} threads × {n_per_thread:,})")
    print(f"{'='*60}")

    def worker(thread_id):
        count = 0
        for i in range(n_per_thread):
            f = make_frame(text=f"Thread {thread_id} msg {i}",
                          agent_id=0xC01FF43E + thread_id)
            result = decode(f)
            if result:
                count += 1
        return count

    t0 = time.perf_counter()
    total = 0
    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        futures = [pool.submit(worker, i) for i in range(n_threads)]
        for f in as_completed(futures):
            total += f.result()
    elapsed = time.perf_counter() - t0

    expected = n_threads * n_per_thread
    print(f"  Total:  {total:,}/{expected:,} frames in {elapsed:.3f}s → {fmt_rate(total, elapsed)}")
    assert total == expected


# ── Test 5: MQTT Pub/Sub Load ──────────────────────────────────

def test_mqtt_load(n=1000, timeout=30):
    """Publish n signed frames and measure receipt latency."""
    print(f"\n{'='*60}")
    print(f"TEST 5: MQTT Pub/Sub Load ({n:,} frames)")
    print(f"{'='*60}")

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("  ⚠️  paho-mqtt not installed, skipping MQTT test")
        return

    received = []
    recv_lock = threading.Lock()
    connected = threading.Event()

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            client.subscribe("egregore/stress/#", qos=1)
            connected.set()

    def on_message(client, userdata, msg):
        t_recv = time.perf_counter()
        with recv_lock:
            received.append((msg.payload, t_recv))

    # Subscriber
    sub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="stress-sub")
    sub.username_pw_set(MQTT_USER, MQTT_PASS)
    sub.on_connect = on_connect
    sub.on_message = on_message
    sub.connect(MQTT_HOST, 1883, 60)
    sub.loop_start()

    if not connected.wait(timeout=5):
        print("  ❌ Failed to connect subscriber")
        sub.loop_stop()
        return

    time.sleep(0.5)  # Let subscription settle

    # Publisher
    pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="stress-pub")
    pub.username_pw_set(MQTT_USER, MQTT_PASS)
    pub.connect(MQTT_HOST, 1883, 60)
    pub.loop_start()

    kp = generate_agent_keys("stress-mqtt")
    send_times = {}

    t0 = time.perf_counter()
    for i in range(n):
        frame = make_frame(text=f"Stress #{i}")
        signed = sign_frame(frame, kp)
        tag = struct.pack("!I", i)
        payload = signed + tag
        send_times[i] = time.perf_counter()
        pub.publish(f"egregore/stress/load", payload, qos=0)
    pub_time = time.perf_counter() - t0

    print(f"  Published {n:,} frames in {pub_time:.3f}s → {fmt_rate(n, pub_time)}")

    # Wait for delivery
    deadline = time.time() + timeout
    while len(received) < n and time.time() < deadline:
        time.sleep(0.1)

    recv_count = len(received)
    elapsed = time.perf_counter() - t0
    loss = n - recv_count
    loss_pct = (loss / n) * 100

    print(f"  Received {recv_count:,}/{n:,} ({loss_pct:.1f}% loss) in {elapsed:.3f}s")

    if recv_count > 0:
        # Latency stats (approximate — based on send/recv perf_counter)
        latencies = []
        for payload, t_recv in received[:recv_count]:
            try:
                idx = struct.unpack("!I", payload[-4:])[0]
                if idx in send_times:
                    latencies.append((t_recv - send_times[idx]) * 1000)  # ms
            except:
                pass

        if latencies:
            print(f"  Latency: min={min(latencies):.2f}ms median={statistics.median(latencies):.2f}ms "
                  f"max={max(latencies):.2f}ms p99={sorted(latencies)[int(len(latencies)*0.99)]:.2f}ms")

    pub.loop_stop()
    sub.loop_stop()
    pub.disconnect()
    sub.disconnect()


# ── Test 6: Rapid Agent Churn ──────────────────────────────────

def test_agent_churn(n_agents=20, msgs_per=50):
    """Simulate many agents connecting, sending, disconnecting."""
    print(f"\n{'='*60}")
    print(f"TEST 6: Agent Churn ({n_agents} agents × {msgs_per} msgs)")
    print(f"{'='*60}")

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("  ⚠️  paho-mqtt not installed, skipping")
        return

    total_sent = 0
    errors = 0
    lock = threading.Lock()

    def agent_lifecycle(agent_num):
        nonlocal total_sent, errors
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, 
                               client_id=f"stress-agent-{agent_num}")
            client.username_pw_set(MQTT_USER, MQTT_PASS)
            client.connect(MQTT_HOST, 1883, 60)
            client.loop_start()

            for i in range(msgs_per):
                frame = make_frame(
                    text=f"Agent {agent_num} msg {i}",
                    agent_id=0xDEAD0000 + agent_num,
                )
                client.publish(f"egregore/stress/churn", frame, qos=0)

            with lock:
                total_sent += msgs_per

            time.sleep(0.2)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            with lock:
                errors += 1

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_agents) as pool:
        futures = [pool.submit(agent_lifecycle, i) for i in range(n_agents)]
        for f in as_completed(futures):
            f.result()
    elapsed = time.perf_counter() - t0

    expected = n_agents * msgs_per
    print(f"  Sent:   {total_sent:,}/{expected:,} in {elapsed:.3f}s → {fmt_rate(total_sent, elapsed)}")
    print(f"  Errors: {errors}")


# ── Main ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🔥 THOUGHTWIRE STRESS TEST")
    print(f"   MQTT: {MQTT_HOST}")
    print(f"   Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    # Protocol layer
    enc_t, dec_t = test_encode_decode_throughput(100_000)
    sign_t, ver_t = test_signing_performance(10_000)
    test_payload_sizes()
    test_concurrent_encoding(8, 10_000)

    # MQTT layer
    test_mqtt_load(1000)
    test_agent_churn(20, 50)

    print(f"\n{'='*60}")
    print("✅ ALL STRESS TESTS COMPLETE")
    print(f"{'='*60}")
