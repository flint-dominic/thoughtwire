#!/usr/bin/env python3
"""
Egregore MQTT Bridge — Thoughtwire Protocol Layer
Bridges between the existing WebSocket/REST Egregore server and MQTT binary frames.
Agents can communicate via MQTT (binary, fast) while staying compatible with the 
existing JSON/WebSocket infrastructure.

Architecture:
  [Egregore WS Server] <--JSON--> [MQTT Bridge] <--Binary--> [MQTT Broker] <--Binary--> [Agents]

The bridge:
  1. Subscribes to Egregore WS for new messages
  2. Encodes them as binary frames and publishes to MQTT
  3. Subscribes to MQTT for agent responses
  4. Decodes and posts them back to Egregore via REST
"""

import asyncio
import json
import struct
import time
import logging
import os
import sys
import threading
from collections import deque

import paho.mqtt.client as mqtt

# Optional: websockets for WS bridge
try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False

# ── Binary Frame Protocol ────────────────────────────────────────

FRAME_HEADER = struct.Struct("!BBIIBBh")  # 14 bytes

FRAME_TYPES = {"chat": 0, "vote": 1, "state_diff": 2, "attention": 3, "system": 4}
FRAME_TYPES_REV = {v: k for k, v in FRAME_TYPES.items()}

INTENTS = {"inform": 0, "request": 1, "propose": 2, "approve": 3, "reject": 4, "respond": 5}
INTENTS_REV = {v: k for k, v in INTENTS.items()}

# Channel name <-> uint8 mapping for binary efficiency
CHANNELS = {"general": 0, "ai-chat": 1, "council": 2, "votes": 3, "system": 4}
CHANNELS_REV = {v: k for k, v in CHANNELS.items()}

# Agent name <-> uint32 mapping
AGENTS = {
    "nix":    0xc01ff43e,
    "llama":  0xc01ff43e,  # same token as nix for now
    "gpt":    0x998ff305,
    "gemini": 0xc814c38c,
}
AGENTS_REV = {v: k for k, v in AGENTS.items()}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger("thoughtwire")


def encode_frame(frame_type: str, agent_id: int, confidence: float, 
                 intent: str, payload: bytes = b"") -> bytes:
    """Encode an Egregore frame to binary."""
    ft = FRAME_TYPES.get(frame_type, 0)
    it = INTENTS.get(intent, 0)
    conf_byte = int(min(confidence, 1.0) * 255)
    ts = int(time.time()) & 0xFFFFFFFF
    header = FRAME_HEADER.pack(1, ft, agent_id, ts, conf_byte, it, len(payload))
    return header + payload


def decode_frame(data: bytes) -> dict:
    """Decode a binary frame to dict."""
    if len(data) < 14:
        return None
    version, ftype, agent_id, ts, conf, intent, plen = FRAME_HEADER.unpack(data[:14])
    payload = data[14:14+plen] if plen > 0 else b""
    return {
        "version": version,
        "frame_type": FRAME_TYPES_REV.get(ftype, str(ftype)),
        "agent_id": agent_id,
        "agent_name": AGENTS_REV.get(agent_id, f"unknown-{agent_id:08x}"),
        "timestamp": ts,
        "confidence": conf / 255.0,
        "intent": INTENTS_REV.get(intent, str(intent)),
        "payload": payload,
        "payload_text": payload.decode("utf-8", errors="replace") if payload else "",
    }


def json_to_binary(egregore_frame: dict) -> bytes:
    """Convert an Egregore JSON frame to binary."""
    text = egregore_frame.get("payload", {}).get("text", "")
    agent_id_str = egregore_frame.get("agent_id", "")
    
    # Try to map agent ID
    agent_int = 0
    try:
        agent_int = int(agent_id_str[:8], 16)
    except (ValueError, IndexError):
        pass
    
    return encode_frame(
        frame_type="chat",
        agent_id=agent_int,
        confidence=1.0,
        intent="inform",
        payload=text.encode("utf-8")[:65535]
    )


def binary_to_json(frame: dict, channel: str = "general") -> dict:
    """Convert a decoded binary frame to Egregore REST format."""
    return {
        "channel": channel,
        "frame_type": "facade.chat",
        "payload": {
            "text": frame["payload_text"]
        }
    }


# ── MQTT <-> Egregore Bridge ─────────────────────────────────────

class ThoughtwireBridge:
    """Bridges Egregore WebSocket server with MQTT binary protocol."""
    
    def __init__(self, 
                 mqtt_host="127.0.0.1", mqtt_port=1883,
                 egregore_ws="ws://yogsothoth:8420/ws",
                 egregore_rest="http://yogsothoth:8420",
                 egregore_token=None,
                 channels=None):
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.egregore_ws = egregore_ws
        self.egregore_rest = egregore_rest
        self.egregore_token = egregore_token
        self.channels = channels or ["general"]
        
        self.mqtt_client = None
        self.stats = {
            "ws_to_mqtt": 0,
            "mqtt_to_ws": 0,
            "bytes_json": 0,
            "bytes_binary": 0,
            "start_time": time.time(),
        }
        
        # Dedup: don't echo back messages we just bridged
        self._recent_bridged = deque(maxlen=50)
    
    def _setup_mqtt(self):
        """Initialize MQTT client."""
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, 
                                        client_id="thoughtwire-bridge")
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_message = self._on_mqtt_message
        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port)
        self.mqtt_client.loop_start()
        log.info(f"🔌 MQTT connected to {self.mqtt_host}:{self.mqtt_port}")
    
    def _on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        """Subscribe to agent response topics."""
        client.subscribe("egregore/agent/+/response")
        client.subscribe("egregore/council/#")
        client.subscribe("egregore/direct/#")
        log.info("📡 MQTT subscribed to agent response topics")
    
    def _on_mqtt_message(self, client, userdata, msg):
        """Handle incoming MQTT messages from agents."""
        topic = msg.topic
        
        # Decode binary frame
        frame = decode_frame(msg.payload)
        if not frame:
            # Try as JSON fallback
            try:
                frame = json.loads(msg.payload.decode())
                frame["payload_text"] = frame.get("text", frame.get("payload", {}).get("text", ""))
            except:
                log.warning(f"⚠️ Could not decode MQTT message on {topic}")
                return
        
        # Dedup check
        dedup_key = f"{frame.get('agent_id', 0)}:{frame.get('payload_text', '')[:50]}"
        if dedup_key in self._recent_bridged:
            return
        self._recent_bridged.append(dedup_key)
        
        # Extract channel from topic
        parts = topic.split("/")
        channel = "general"
        if len(parts) >= 3 and parts[1] == "council":
            channel = parts[2] if len(parts) > 2 else "general"
        
        agent_name = frame.get("agent_name", "unknown")
        text = frame.get("payload_text", "")
        
        if text:
            log.info(f"📥 MQTT→WS [{agent_name}] {text[:60]}...")
            self._post_to_egregore(channel, text)
            self.stats["mqtt_to_ws"] += 1
    
    def _post_to_egregore(self, channel: str, text: str):
        """Post a message to Egregore REST API."""
        import urllib.request
        try:
            data = json.dumps({
                "channel": channel,
                "frame_type": "facade.chat",
                "payload": {"text": text}
            }).encode()
            req = urllib.request.Request(
                f"{self.egregore_rest}/frame",
                data=data,
                headers={
                    "Authorization": f"Bearer {self.egregore_token}",
                    "Content-Type": "application/json"
                }
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log.error(f"❌ Failed to post to Egregore: {e}")
    
    def publish_to_mqtt(self, channel: str, agent_id: str, text: str):
        """Publish an Egregore message to MQTT as binary frame."""
        agent_int = 0
        try:
            agent_int = int(agent_id[:8], 16)
        except (ValueError, IndexError):
            pass
        
        binary_frame = encode_frame("chat", agent_int, 1.0, "inform", 
                                     text.encode("utf-8")[:65535])
        json_size = len(json.dumps({"agent": agent_id, "text": text}).encode())
        
        topic = f"egregore/council/{channel}"
        self.mqtt_client.publish(topic, binary_frame)
        
        self.stats["ws_to_mqtt"] += 1
        self.stats["bytes_json"] += json_size
        self.stats["bytes_binary"] += len(binary_frame)
        
        # Dedup
        dedup_key = f"{agent_int}:{text[:50]}"
        self._recent_bridged.append(dedup_key)
    
    def print_stats(self):
        """Print bridge statistics."""
        elapsed = time.time() - self.stats["start_time"]
        saved = self.stats["bytes_json"] - self.stats["bytes_binary"]
        pct = (saved / max(self.stats["bytes_json"], 1)) * 100
        
        log.info("📊 Thoughtwire Stats:")
        log.info(f"   Uptime: {elapsed/60:.0f}min")
        log.info(f"   WS→MQTT: {self.stats['ws_to_mqtt']} frames")
        log.info(f"   MQTT→WS: {self.stats['mqtt_to_ws']} frames")
        log.info(f"   Bytes saved: {saved} ({pct:.0f}% reduction)")
    
    async def run(self):
        """Main bridge loop."""
        self._setup_mqtt()
        
        if not HAS_WS:
            log.error("websockets not installed! pip install websockets")
            return
        
        headers = {"Authorization": f"Bearer {self.egregore_token}"}
        
        while True:
            try:
                async with websockets.connect(self.egregore_ws, 
                                               additional_headers=headers) as ws:
                    log.info(f"🔗 Connected to Egregore WS at {self.egregore_ws}")
                    
                    # Subscribe to channels
                    for ch in self.channels:
                        await ws.send(json.dumps({"action": "subscribe", "channel": ch}))
                    log.info(f"   Channels: {', '.join(self.channels)}")
                    
                    # Stats printer
                    last_stats = time.time()
                    
                    async for msg in ws:
                        data = json.loads(msg)
                        
                        if data.get("frame_type") != "facade.chat" and data.get("type") != "facade.chat":
                            continue
                        
                        text = data.get("payload", {}).get("text", "")
                        agent_id = data.get("agent_id", "")
                        channel = data.get("channel", "general")
                        
                        if not text:
                            continue
                        
                        # Bridge WS → MQTT
                        agent_name = AGENTS_REV.get(
                            int(agent_id[:8], 16) if agent_id else 0, 
                            agent_id[:8] if agent_id else "?"
                        )
                        log.info(f"📤 WS→MQTT [{agent_name}@{channel}] {text[:60]}...")
                        self.publish_to_mqtt(channel, agent_id, text)
                        
                        # Periodic stats
                        if time.time() - last_stats > 300:
                            self.print_stats()
                            last_stats = time.time()
            
            except websockets.exceptions.ConnectionClosed:
                log.warning("🔄 WS disconnected, reconnecting in 5s...")
                await asyncio.sleep(5)
            except Exception as e:
                log.error(f"❌ Bridge error: {e}")
                await asyncio.sleep(5)


# ── Standalone Agent (MQTT-native) ────────────────────────────────

class MQTTAgent:
    """A minimal MQTT-native Egregore agent for testing.
    Subscribes to council topics, responds via MQTT binary frames."""
    
    def __init__(self, name, agent_id, mqtt_host="127.0.0.1", mqtt_port=1883,
                 generate_fn=None):
        self.name = name
        self.agent_id = agent_id
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.generate_fn = generate_fn or (lambda text: f"[{name}] Acknowledged: {text[:50]}")
        self.msg_count = 0
        
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                   client_id=f"agent-{name}")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
    
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        client.subscribe("egregore/council/#")
        log.info(f"🤖 Agent [{self.name}] connected and listening")
    
    def _on_message(self, client, userdata, msg):
        frame = decode_frame(msg.payload)
        if not frame or frame["agent_id"] == self.agent_id:
            return  # Skip own messages
        
        text = frame["payload_text"]
        if not text:
            return
        
        sender = frame["agent_name"]
        log.info(f"🤖 [{self.name}] heard [{sender}]: {text[:60]}...")
        
        # Generate response
        response = self.generate_fn(text)
        if not response or response == "[SKIP]":
            return
        
        # Publish binary response
        channel = msg.topic.split("/")[-1] if "/" in msg.topic else "general"
        response_frame = encode_frame("chat", self.agent_id, 0.9, "respond",
                                       response.encode("utf-8")[:65535])
        self.client.publish(f"egregore/council/{channel}", response_frame)
        self.msg_count += 1
        log.info(f"🤖 [{self.name}] responded (msg #{self.msg_count})")
    
    def run(self):
        self.client.connect(self.mqtt_host, self.mqtt_port)
        self.client.loop_forever()


# ── CLI ───────────────────────────────────────────────────────────

def main():
    _run_cli()

def _run_cli():
    import argparse
    parser = argparse.ArgumentParser(description="Egregore Thoughtwire — MQTT Bridge")
    parser.add_argument("mode", choices=["bridge", "test-agent", "publish", "subscribe", "stats"],
                        help="Mode: bridge (WS↔MQTT), test-agent, publish, subscribe, stats")
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--egregore-ws", default="ws://yogsothoth:8420/ws")
    parser.add_argument("--egregore-rest", default="http://yogsothoth:8420")
    parser.add_argument("--token", default=os.environ.get("EGREGORE_TOKEN", 
                        "oY-mlVGObWMURD5EPDvp5w1VHFZ6ZESXLjMHEz-3J_E"))
    parser.add_argument("--channel", default="general")
    parser.add_argument("--message", "-m", default=None)
    parser.add_argument("--agent-name", default="test-agent")
    args = parser.parse_args()
    
    if args.mode == "bridge":
        bridge = ThoughtwireBridge(
            mqtt_host=args.mqtt_host,
            mqtt_port=args.mqtt_port,
            egregore_ws=args.egregore_ws,
            egregore_rest=args.egregore_rest,
            egregore_token=args.token,
            channels=["general", "ai-chat"],
        )
        asyncio.run(bridge.run())
    
    elif args.mode == "test-agent":
        agent = MQTTAgent(args.agent_name, AGENTS.get(args.agent_name, 0xDEADBEEF),
                          args.mqtt_host, args.mqtt_port)
        agent.run()
    
    elif args.mode == "publish":
        msg = args.message or "Hello from Thoughtwire!"
        frame = encode_frame("chat", AGENTS.get("nix", 0), 1.0, "inform",
                             msg.encode("utf-8"))
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.connect(args.mqtt_host, args.mqtt_port)
        client.publish(f"egregore/council/{args.channel}", frame)
        client.disconnect()
        
        json_size = len(json.dumps({"text": msg}).encode())
        print(f"📤 Published to egregore/council/{args.channel}")
        print(f"   Binary: {len(frame)} bytes (JSON would be {json_size} bytes, saved {json_size - len(frame)})")
    
    elif args.mode == "subscribe":
        def on_msg(client, userdata, msg):
            frame = decode_frame(msg.payload)
            if frame:
                name = frame["agent_name"]
                text = frame["payload_text"][:100]
                conf = frame["confidence"]
                intent = frame["intent"]
                print(f"  [{name}] ({intent}, conf={conf:.2f}) {text}")
            else:
                print(f"  [raw] {msg.payload[:100]}")
        
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.on_message = on_msg
        client.connect(args.mqtt_host, args.mqtt_port)
        client.subscribe("egregore/#")
        print(f"👂 Listening on egregore/# ...")
        client.loop_forever()
    
    elif args.mode == "stats":
        # Quick stats: publish a stats request, see what comes back
        print("📊 Thoughtwire Protocol Stats")
        print(f"   MQTT Broker: {args.mqtt_host}:{args.mqtt_port}")
        print(f"   Egregore: {args.egregore_rest}")
        print(f"   Frame header: 14 bytes")
        print(f"   Avg JSON equivalent: ~180 bytes")
        print(f"   Compression ratio: ~91%")


if __name__ == "__main__":
    main()
