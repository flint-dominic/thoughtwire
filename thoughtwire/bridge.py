"""
Egregore MQTT Bridge — Bidirectional bridge between Egregore WS/REST and MQTT binary frames.

Architecture:
  [Egregore WS Server] <--JSON--> [MQTT Bridge] <--Binary--> [MQTT Broker] <--Binary--> [Agents]
"""

import asyncio
import json
import logging
import os
import time
from collections import deque

import paho.mqtt.client as mqtt

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False

from .protocol import (
    encode, decode, FRAME_V1_HEADER, AGENTS, AGENTS_REV,
    from_egregore_json, to_egregore_json, validate_channel,
)

log = logging.getLogger("thoughtwire.bridge")

# Re-export for backward compat
FRAME_HEADER = FRAME_V1_HEADER
FRAME_TYPES = {k: v for k, v in __import__('thoughtwire.protocol', fromlist=['FRAME_TYPES']).FRAME_TYPES.items()}
FRAME_TYPES_REV = {v: k for k, v in FRAME_TYPES.items()}
INTENTS = {k: v for k, v in __import__('thoughtwire.protocol', fromlist=['INTENTS']).INTENTS.items()}
INTENTS_REV = {v: k for k, v in INTENTS.items()}

# Legacy aliases
encode_frame = encode
decode_frame = decode


class ThoughtwireBridge:
    """Bridges Egregore WebSocket server with MQTT binary protocol."""

    def __init__(self, mqtt_host="127.0.0.1", mqtt_port=1883,
                 mqtt_user=None, mqtt_pass=None,
                 egregore_ws="ws://yogsothoth:8420/ws",
                 egregore_rest="http://yogsothoth:8420",
                 egregore_token=None, channels=None):
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.mqtt_user = mqtt_user
        self.mqtt_pass = mqtt_pass
        self.egregore_ws = egregore_ws
        self.egregore_rest = egregore_rest
        self.egregore_token = egregore_token
        self.channels = channels or ["general"]

        self.mqtt_client = None
        self.stats = {
            "ws_to_mqtt": 0, "mqtt_to_ws": 0,
            "bytes_json": 0, "bytes_binary": 0,
            "start_time": time.time(),
        }
        self._recent_bridged = deque(maxlen=50)

    def _setup_mqtt(self):
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                        client_id="thoughtwire-bridge")
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_message = self._on_mqtt_message
        if self.mqtt_user and self.mqtt_pass:
            self.mqtt_client.username_pw_set(self.mqtt_user, self.mqtt_pass)
        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port)
        self.mqtt_client.loop_start()
        auth = "authenticated" if self.mqtt_user else "anonymous"
        log.info(f"🔌 MQTT connected to {self.mqtt_host}:{self.mqtt_port} ({auth})")

    def _on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        client.subscribe("egregore/agent/+/response")
        client.subscribe("egregore/council/#")
        client.subscribe("egregore/direct/#")
        log.info("📡 MQTT subscribed to agent response topics")

    def _on_mqtt_message(self, client, userdata, msg):
        frame = decode(msg.payload)
        if not frame:
            try:
                frame = json.loads(msg.payload.decode())
                frame["payload_text"] = frame.get("text", frame.get("payload", {}).get("text", ""))
                frame["agent_id"] = 0
                frame["agent_name"] = "unknown"
            except:
                log.warning(f"⚠️ Could not decode MQTT message on {msg.topic}")
                return

        dedup_key = f"{frame.get('agent_id', 0)}:{frame.get('payload_text', '')[:50]}"
        if dedup_key in self._recent_bridged:
            return
        self._recent_bridged.append(dedup_key)

        parts = msg.topic.split("/")
        channel = parts[2] if len(parts) > 2 and parts[1] == "council" else "general"
        text = frame.get("payload_text", "")

        if text:
            agent_name = frame.get("agent_name", "unknown")
            log.info(f"📥 MQTT→WS [{agent_name}] {text[:60]}...")
            self._post_to_egregore(channel, text)
            self.stats["mqtt_to_ws"] += 1

    def _post_to_egregore(self, channel: str, text: str):
        import urllib.request
        try:
            data = json.dumps({
                "channel": channel,
                "frame_type": "facade.chat",
                "payload": {"text": text}
            }).encode()
            req = urllib.request.Request(
                f"{self.egregore_rest}/frame", data=data,
                headers={
                    "Authorization": f"Bearer {self.egregore_token}",
                    "Content-Type": "application/json"
                }
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log.error(f"❌ Failed to post to Egregore: {e}")

    def publish_to_mqtt(self, channel: str, agent_id: str, text: str):
        agent_int = 0
        try:
            agent_int = int(agent_id[:8], 16)
        except (ValueError, IndexError):
            pass

        binary_frame = encode("chat", agent_int, 1.0, "inform",
                               text.encode("utf-8")[:65535])
        json_size = len(json.dumps({"agent": agent_id, "text": text}).encode())

        topic = f"egregore/council/{channel}"
        self.mqtt_client.publish(topic, binary_frame)

        self.stats["ws_to_mqtt"] += 1
        self.stats["bytes_json"] += json_size
        self.stats["bytes_binary"] += len(binary_frame)

        dedup_key = f"{agent_int}:{text[:50]}"
        self._recent_bridged.append(dedup_key)

    def print_stats(self):
        elapsed = time.time() - self.stats["start_time"]
        saved = self.stats["bytes_json"] - self.stats["bytes_binary"]
        pct = (saved / max(self.stats["bytes_json"], 1)) * 100
        log.info(f"📊 Uptime: {elapsed/60:.0f}min | "
                 f"WS→MQTT: {self.stats['ws_to_mqtt']} | "
                 f"MQTT→WS: {self.stats['mqtt_to_ws']} | "
                 f"Saved: {saved}B ({pct:.0f}%)")

    async def run(self):
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
                    for ch in self.channels:
                        await ws.send(json.dumps({"action": "subscribe", "channel": ch}))
                    log.info(f"   Channels: {', '.join(self.channels)}")

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

                        agent_name = AGENTS_REV.get(
                            int(agent_id[:8], 16) if agent_id else 0,
                            agent_id[:8] if agent_id else "?"
                        )
                        log.info(f"📤 WS→MQTT [{agent_name}@{channel}] {text[:60]}...")
                        self.publish_to_mqtt(channel, agent_id, text)

                        if time.time() - last_stats > 300:
                            self.print_stats()
                            last_stats = time.time()

            except websockets.exceptions.ConnectionClosed:
                log.warning("🔄 WS disconnected, reconnecting in 5s...")
                await asyncio.sleep(5)
            except Exception as e:
                log.error(f"❌ Bridge error: {e}")
                await asyncio.sleep(5)
