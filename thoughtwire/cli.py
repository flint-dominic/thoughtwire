"""
Thoughtwire CLI — Command-line interface for the Thoughtwire protocol.
"""

import argparse
import json
import logging
import os
import sys
import time

from .protocol import (
    encode, decode, FRAME_TYPES, INTENTS, AGENTS, AGENTS_REV,
    frame_size_comparison, validate_channel, VERSION_1, VERSION_2,
)


def load_env():
    """Load .env file if present."""
    for path in ['.env', os.path.expanduser('~/.thoughtwire/.env')]:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        os.environ.setdefault(k.strip(), v.strip())
            break


def cmd_bridge(args):
    """Run the Egregore↔MQTT bridge."""
    import asyncio
    from .bridge import ThoughtwireBridge
    
    bridge = ThoughtwireBridge(
        mqtt_host=args.mqtt_host, mqtt_port=args.mqtt_port,
        mqtt_user=args.mqtt_user, mqtt_pass=args.mqtt_pass,
        egregore_ws=args.egregore_ws, egregore_rest=args.egregore_rest,
        egregore_token=args.token,
        channels=args.channels.split(",") if args.channels else ["general", "ai-chat"],
    )
    asyncio.run(bridge.run())


def cmd_subscribe(args):
    """Subscribe to MQTT and display frames."""
    import paho.mqtt.client as mqtt
    
    def on_msg(client, userdata, msg):
        frame = decode(msg.payload)
        if frame:
            name = frame["agent_name"]
            ftype = frame["frame_type"]
            intent = frame["intent"]
            conf = frame["confidence"]
            text = frame["payload_text"][:120]
            signed = "🔏" if frame.get("signed") else "  "
            ver = f"v{frame['version']}"
            print(f"{signed} {ver} [{name}] ({ftype}/{intent} conf={conf:.2f}) {text}")
        else:
            try:
                data = json.loads(msg.payload.decode())
                print(f"  📋 [JSON] {msg.topic}: {str(data)[:120]}")
            except:
                print(f"  ❓ [raw] {msg.topic}: {msg.payload[:80]}")
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                          client_id="tw-subscriber")
    if args.mqtt_user and args.mqtt_pass:
        client.username_pw_set(args.mqtt_user, args.mqtt_pass)
    client.on_message = on_msg
    client.connect(args.mqtt_host, args.mqtt_port)
    
    topic = args.topic or "egregore/#"
    client.subscribe(topic)
    print(f"👂 Listening on {topic} at {args.mqtt_host}:{args.mqtt_port}")
    print(f"   Press Ctrl+C to stop\n")
    
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n👋 Disconnected")
        client.disconnect()


def cmd_publish(args):
    """Publish a binary frame."""
    import paho.mqtt.client as mqtt
    
    text = args.message or "Hello from Thoughtwire!"
    payload = text.encode("utf-8")
    
    agent_id = AGENTS.get(args.agent, 0)
    frame = encode(args.type, agent_id, args.confidence, args.intent, payload)
    
    # Optionally sign
    if args.sign:
        from .signing import load_agent_keys, sign_frame
        kp = load_agent_keys(args.sign)
        if kp.has_keys:
            frame = sign_frame(frame, kp)
            print(f"🔏 Signed as {args.sign}")
        else:
            print(f"⚠️ No keys found for {args.sign}, sending unsigned")
    
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if args.mqtt_user and args.mqtt_pass:
        client.username_pw_set(args.mqtt_user, args.mqtt_pass)
    client.connect(args.mqtt_host, args.mqtt_port)
    
    channel = validate_channel(args.channel)
    topic = f"egregore/council/{channel}"
    client.publish(topic, frame)
    client.disconnect()
    
    comp = frame_size_comparison(text)
    print(f"📤 Published to {topic}")
    print(f"   Frame: {len(frame)} bytes (JSON equiv: {comp['json_bytes']}B, "
          f"saved {comp['saved_bytes']}B / {comp['reduction_pct']:.0f}%)")


def cmd_agent(args):
    """Run a test agent."""
    from .agent import EchoAgent, SilentAgent
    
    AgentClass = SilentAgent if args.silent else EchoAgent
    agent = AgentClass(
        name=args.name, mqtt_host=args.mqtt_host, mqtt_port=args.mqtt_port,
        mqtt_user=args.mqtt_user, mqtt_pass=args.mqtt_pass,
        channels=args.channels.split(",") if args.channels else ["general"],
        sign_frames=bool(args.sign),
    )
    
    try:
        agent.run()
    except KeyboardInterrupt:
        s = agent.stats()
        print(f"\n📊 {s['name']}: {s['messages_sent']} msgs in {s['uptime_minutes']:.1f}min")


def cmd_keygen(args):
    """Generate agent keypair."""
    from .signing import generate_agent_keys, KEYS_DIR
    
    kp = generate_agent_keys(args.name)
    print(f"🔑 Generated keypair for '{args.name}'")
    print(f"   Public key: {kp.public_hex}")
    print(f"   Stored in:  {KEYS_DIR}/")


def cmd_keylist(args):
    """List all agent keys."""
    from .signing import list_keys, KEYS_DIR
    
    keys = list_keys()
    if not keys:
        print(f"No keys found in {KEYS_DIR}")
        return
    
    print(f"🔑 Agent Keys ({KEYS_DIR}):\n")
    for name, hexkey in keys.items():
        if hexkey.startswith("("):
            print(f"  {name:>12}: {hexkey}")
        else:
            print(f"  {name:>12}: {hexkey[:16]}...{hexkey[-8:]}")


def cmd_decode(args):
    """Decode a hex-encoded frame."""
    try:
        data = bytes.fromhex(args.hex.replace(" ", "").replace("0x", ""))
    except ValueError:
        print("❌ Invalid hex string")
        sys.exit(1)
    
    frame = decode(data)
    if frame:
        # Pretty print
        print(f"  Version:    v{frame['version']}")
        print(f"  Type:       {frame['frame_type']} ({frame['frame_type_id']})")
        print(f"  Agent:      {frame['agent_name']} (0x{frame['agent_id']:08X})")
        print(f"  Timestamp:  {frame['timestamp']}")
        print(f"  Confidence: {frame['confidence']:.2f}")
        print(f"  Intent:     {frame['intent']} ({frame['intent_id']})")
        print(f"  Payload:    {frame['payload_len']} bytes")
        if frame['payload_text']:
            print(f"  Text:       {frame['payload_text'][:200]}")
        print(f"  Signed:     {frame['signed']}")
        print(f"  Total:      {frame['raw_len']} bytes")
    else:
        print("❌ Could not decode frame")


def cmd_encode(args):
    """Encode a frame and print hex."""
    payload = (args.message or "").encode("utf-8")
    agent_id = AGENTS.get(args.agent, 0)
    frame = encode(args.type, agent_id, args.confidence, args.intent, payload)
    
    print(f"Hex: {frame.hex()}")
    print(f"Len: {len(frame)} bytes")
    
    # Verify roundtrip
    decoded = decode(frame)
    if decoded:
        print(f"  ✅ Roundtrip OK: {decoded['frame_type']}/{decoded['intent']} "
              f"conf={decoded['confidence']:.2f} \"{decoded['payload_text'][:60]}\"")


def cmd_schema(args):
    """Generate schema in various formats."""
    from .schema import generate, FORMATS
    
    fmt = args.format
    try:
        filename, content = generate(fmt)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)
    
    if args.output:
        outpath = args.output
    elif args.stdout:
        print(content)
        return
    else:
        outpath = filename
    
    with open(outpath, "w") as f:
        f.write(content)
    print(f"📐 Generated {outpath} ({len(content)} bytes)")
    
    if not args.stdout:
        # Show a preview
        lines = content.strip().split("\n")
        preview = "\n".join(lines[:8])
        print(f"\n{preview}")
        if len(lines) > 8:
            print(f"   ... ({len(lines)} lines total)")


def cmd_stats(args):
    """Show protocol statistics."""
    print("📊 Thoughtwire Protocol")
    print(f"   Version:     v2 (backward-compatible with v1)")
    print(f"   V1 Header:   14 bytes")
    print(f"   V2 Header:   16 bytes + 64-byte Ed25519 signature")
    print(f"   MQTT Broker:  {args.mqtt_host}:{args.mqtt_port}")
    
    print(f"\n   Frame Types:  {', '.join(FRAME_TYPES.keys())}")
    print(f"   Intents:      {', '.join(INTENTS.keys())}")
    print(f"   Known Agents: {', '.join(AGENTS.keys())}")
    
    print(f"\n   Size Comparison:")
    for text in ["yes", "Hello world", "A" * 50, "B" * 200]:
        c = frame_size_comparison(text)
        label = f'"{text[:20]}{"..." if len(text) > 20 else ""}"'
        print(f"   {label:>25}: {c['binary_bytes']:>4}B vs {c['json_bytes']:>4}B JSON "
              f"({c['reduction_pct']:.0f}% smaller)")


def main():
    """Thoughtwire CLI entry point."""
    load_env()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    parser = argparse.ArgumentParser(
        prog="thoughtwire",
        description="Thoughtwire — Binary communication protocol for AI agent networks"
    )
    sub = parser.add_subparsers(dest="command", help="Command")
    
    # Shared MQTT args
    def add_mqtt_args(p):
        p.add_argument("--mqtt-host", default=os.environ.get("MQTT_HOST", "127.0.0.1"))
        p.add_argument("--mqtt-port", type=int, default=int(os.environ.get("MQTT_PORT", "1883")))
        p.add_argument("--mqtt-user", default=os.environ.get("MQTT_USER"))
        p.add_argument("--mqtt-pass", default=os.environ.get("MQTT_PASS"))
    
    # bridge
    p = sub.add_parser("bridge", help="Run Egregore↔MQTT bridge")
    add_mqtt_args(p)
    p.add_argument("--egregore-ws", default=os.environ.get("EGREGORE_WS", "ws://yogsothoth:8420/ws"))
    p.add_argument("--egregore-rest", default=os.environ.get("EGREGORE_REST", "http://yogsothoth:8420"))
    p.add_argument("--token", default=os.environ.get("EGREGORE_TOKEN"))
    p.add_argument("--channels", default="general,ai-chat")
    
    # subscribe
    p = sub.add_parser("subscribe", help="Listen to MQTT traffic")
    add_mqtt_args(p)
    p.add_argument("--topic", default=None, help="MQTT topic (default: egregore/#)")
    
    # publish
    p = sub.add_parser("publish", help="Send a binary frame")
    add_mqtt_args(p)
    p.add_argument("-m", "--message", required=True, help="Message text")
    p.add_argument("-c", "--channel", default="general")
    p.add_argument("-t", "--type", default="chat", choices=FRAME_TYPES.keys())
    p.add_argument("-i", "--intent", default="inform", choices=INTENTS.keys())
    p.add_argument("--confidence", type=float, default=1.0)
    p.add_argument("--agent", default="nix")
    p.add_argument("--sign", default=None, metavar="AGENT", help="Sign with agent's key")
    
    # agent
    p = sub.add_parser("agent", help="Run a test agent")
    add_mqtt_args(p)
    p.add_argument("name", help="Agent name")
    p.add_argument("--channels", default="general")
    p.add_argument("--silent", action="store_true", help="Listen-only mode")
    p.add_argument("--sign", default=None, metavar="AGENT", help="Sign outgoing frames")
    
    # keygen
    p = sub.add_parser("keygen", help="Generate agent keypair")
    p.add_argument("name", help="Agent name")
    
    # keylist
    sub.add_parser("keylist", help="List agent public keys")
    
    # decode
    p = sub.add_parser("decode", help="Decode a hex frame")
    p.add_argument("hex", help="Hex-encoded frame")
    
    # encode
    p = sub.add_parser("encode", help="Encode a frame to hex")
    p.add_argument("-m", "--message", default="", help="Payload text")
    p.add_argument("-t", "--type", default="chat", choices=FRAME_TYPES.keys())
    p.add_argument("-i", "--intent", default="inform", choices=INTENTS.keys())
    p.add_argument("--confidence", type=float, default=1.0)
    p.add_argument("--agent", default="nix")
    
    # schema
    p = sub.add_parser("schema", help="Generate protocol schemas")
    p.add_argument("--format", "-f", required=True,
                   choices=["protobuf", "proto", "flatbuffers", "fbs", "json", "jsonschema", "c", "rust"],
                   help="Output format")
    p.add_argument("--output", "-o", default=None, help="Output file path")
    p.add_argument("--stdout", action="store_true", help="Print to stdout instead of file")

    # stats
    p = sub.add_parser("stats", help="Protocol statistics")
    add_mqtt_args(p)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    commands = {
        "bridge": cmd_bridge, "subscribe": cmd_subscribe,
        "publish": cmd_publish, "agent": cmd_agent,
        "keygen": cmd_keygen, "keylist": cmd_keylist,
        "decode": cmd_decode, "encode": cmd_encode,
        "stats": cmd_stats, "schema": cmd_schema,
    }
    
    commands[args.command](args)
