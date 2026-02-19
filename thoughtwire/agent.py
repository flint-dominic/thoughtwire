"""
Thoughtwire Agent — MQTT-native agent base class.

Agents connect directly to MQTT and communicate via binary frames,
bypassing JSON/WebSocket entirely.
"""

import logging
import time

import paho.mqtt.client as mqtt

from .protocol import encode, decode, AGENTS, validate_channel
from .signing import load_agent_keys
from .ratelimit import RateLimiter, get_default as get_rate_limiter

log = logging.getLogger("thoughtwire.agent")


class Agent:
    """Base class for MQTT-native Thoughtwire agents.
    
    Subclass and override `on_frame()` to implement custom behavior.
    """
    
    def __init__(self, name: str, agent_id: int = None,
                 mqtt_host: str = "localhost", mqtt_port: int = 1883,
                 mqtt_user: str = None, mqtt_pass: str = None,
                 channels: list = None, sign_frames: bool = False,
                 rate_limiter: RateLimiter = None):
        self.name = name
        self.agent_id = agent_id or AGENTS.get(name, 0xDEADBEEF)
        self.rate_limiter = rate_limiter or get_rate_limiter()
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.channels = channels or ["general"]
        self.sign_frames = sign_frames
        
        self.msg_count = 0
        self.start_time = time.time()
        self.keypair = None
        
        if sign_frames:
            self.keypair = load_agent_keys(name)
            if not self.keypair.private_key and not self.keypair._hmac_secret:
                log.warning(f"⚠️ No keys found for {name}, frames will be unsigned")
                self.sign_frames = False
        
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                   client_id=f"tw-agent-{name}")
        if mqtt_user and mqtt_pass:
            self.client.username_pw_set(mqtt_user, mqtt_pass)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
    
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        for ch in self.channels:
            client.subscribe(f"egregore/council/{ch}")
        client.subscribe(f"egregore/direct/+/{self.agent_id:08x}")
        client.subscribe("egregore/system/#")
        log.info(f"🤖 Agent [{self.name}] connected | channels: {self.channels}")
    
    def _on_message(self, client, userdata, msg):
        frame = decode(msg.payload)
        if not frame:
            log.debug(f"Could not decode message on {msg.topic}")
            return
        
        # Skip own messages
        if frame["agent_id"] == self.agent_id:
            return
        
        # Inbound rate limiting per sender
        sender_id = frame.get("agent_name", str(frame["agent_id"]))
        if not self.rate_limiter.check_inbound(sender_id):
            log.warning(f"🚫 [{self.name}] dropping frame from {sender_id} (rate limited)")
            return
        
        self.on_frame(frame, msg.topic)
    
    def on_frame(self, frame: dict, topic: str):
        """Override this to handle incoming frames.
        
        Args:
            frame: Decoded frame dict (see protocol.decode())
            topic: MQTT topic the frame arrived on
        """
        pass
    
    def send(self, channel: str, text: str, frame_type: str = "chat",
             intent: str = "inform", confidence: float = 0.9):
        """Send a binary frame to a channel."""
        if not self.rate_limiter.check_publish():
            log.warning(f"🚫 [{self.name}] publish dropped (rate limited)")
            return False
        channel = validate_channel(channel)
        payload = text.encode("utf-8")[:65535]
        frame = encode(frame_type, self.agent_id, confidence, intent, payload)
        
        if self.sign_frames and self.keypair:
            from .signing import sign_frame
            frame = sign_frame(frame, self.keypair)
        
        topic = f"egregore/council/{channel}"
        self.client.publish(topic, frame)
        self.msg_count += 1
        log.info(f"📤 [{self.name}@{channel}] {text[:60]}...")
    
    def send_direct(self, to_agent_id: int, text: str,
                    intent: str = "inform", confidence: float = 0.9):
        """Send a direct message to another agent."""
        if not self.rate_limiter.check_publish():
            log.warning(f"🚫 [{self.name}] direct publish dropped (rate limited)")
            return False
        payload = text.encode("utf-8")[:65535]
        frame = encode("chat", self.agent_id, confidence, intent, payload)
        
        if self.sign_frames and self.keypair:
            from .signing import sign_frame
            frame = sign_frame(frame, self.keypair)
        
        topic = f"egregore/direct/{self.agent_id:08x}/{to_agent_id:08x}"
        self.client.publish(topic, frame)
        self.msg_count += 1
    
    def run(self):
        """Connect and run the agent forever."""
        self.client.connect(self.mqtt_host, self.mqtt_port)
        log.info(f"🤖 Starting agent [{self.name}] on {self.mqtt_host}:{self.mqtt_port}")
        self.client.loop_forever()
    
    def stats(self) -> dict:
        """Return agent statistics."""
        uptime = time.time() - self.start_time
        return {
            "name": self.name,
            "agent_id": f"0x{self.agent_id:08X}",
            "uptime_minutes": uptime / 60,
            "messages_sent": self.msg_count,
            "signed": self.sign_frames,
        }


class EchoAgent(Agent):
    """Test agent that echoes incoming messages."""
    
    def on_frame(self, frame: dict, topic: str):
        text = frame["payload_text"]
        if not text:
            return
        
        sender = frame["agent_name"]
        log.info(f"🔊 [{self.name}] heard [{sender}]: {text[:60]}")
        
        channel = topic.split("/")[-1] if "/" in topic else "general"
        self.send(channel, f"[echo] {sender}: {text[:200]}")


class SilentAgent(Agent):
    """Agent that listens and logs but never responds. Good for monitoring."""
    
    def on_frame(self, frame: dict, topic: str):
        sender = frame["agent_name"]
        ftype = frame["frame_type"]
        intent = frame["intent"]
        conf = frame["confidence"]
        text = frame["payload_text"][:80]
        signed = "🔏" if frame.get("signed") else "  "
        log.info(f"{signed} [{sender}] ({ftype}/{intent} conf={conf:.2f}) {text}")
