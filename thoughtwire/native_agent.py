"""
Thoughtwire Native Agent — Pure MQTT binary agent, no Egregore bridge needed.

This is the first agent that speaks Thoughtwire natively:
- Connects directly to MQTT with auth
- Sends/receives signed v2 frames
- No JSON, no WebSocket, no REST
- Pure binary protocol
"""

import logging
import time
import json

from .agent import Agent
from .protocol import decode, FRAME_TYPES, INTENTS, AGENTS_REV
from .signing import load_agent_keys, sign_frame, verify_frame, init_all_keys, get_replay_guard

log = logging.getLogger("thoughtwire.native")


class NativeAgent(Agent):
    """MQTT-native agent with frame signing and verification.
    
    This is the reference implementation of a Thoughtwire-native agent.
    It verifies incoming signed frames and signs all outgoing frames.
    """
    
    def __init__(self, name, agent_id=None, 
                 mqtt_host="localhost", mqtt_port=1883,
                 mqtt_user=None, mqtt_pass=None,
                 channels=None, handler=None):
        super().__init__(
            name=name, agent_id=agent_id,
            mqtt_host=mqtt_host, mqtt_port=mqtt_port,
            mqtt_user=mqtt_user, mqtt_pass=mqtt_pass,
            channels=channels or ["general"],
            sign_frames=True,
        )
        self._handler = handler
        self._known_keys = init_all_keys(["nix", "llama", "gpt", "gemini", "bridge"])
        self._replay_guard = get_replay_guard(max_age=300)
        self.verified_count = 0
        self.unverified_count = 0
        self.rejected_count = 0
    
    def _on_message(self, client, userdata, msg):
        """Override to add replay protection before frame processing."""
        from .protocol import decode
        frame = decode(msg.payload)
        if not frame:
            return
        if frame["agent_id"] == self.agent_id:
            return
        
        # Replay protection
        accepted, reason = self._replay_guard.check(msg.payload, frame.get("timestamp", 0))
        if not accepted:
            self.rejected_count += 1
            log.warning(f"🛡️ REPLAY REJECTED from {frame.get('agent_name', '?')}: {reason}")
            return
        
        self.on_frame(frame, msg.topic)
    
    def on_frame(self, frame, topic):
        """Process incoming frame with signature verification."""
        sender = frame.get("agent_name", "unknown")
        text = frame.get("payload_text", "")
        
        if not text:
            return
        
        # Verify signature if v2
        verified = False
        if frame.get("signed"):
            # Re-verify against known keys (frame was already decoded, 
            # but we want to know WHO signed it)
            # The raw bytes aren't available here, so we trust the decode
            verified = frame.get("verified", False)
            if verified:
                self.verified_count += 1
                log.info(f"🔏✅ [{sender}] (verified) {text[:60]}")
            else:
                self.unverified_count += 1
                log.warning(f"🔏❌ [{sender}] (UNVERIFIED signature) {text[:60]}")
        else:
            self.unverified_count += 1
            log.info(f"   [{sender}] (unsigned) {text[:60]}")
        
        # Call user handler if provided
        if self._handler:
            response = self._handler(frame, topic, verified)
            if response:
                channel = topic.split("/")[-1] if "/" in topic else "general"
                self.send(channel, response)
    
    def stats(self):
        """Extended stats with verification counts."""
        base = super().stats()
        base.update({
            "verified_frames": self.verified_count,
            "unverified_frames": self.unverified_count,
            "rejected_frames": self.rejected_count,
            "replay_guard": self._replay_guard.stats(),
        })
        return base


class WatchdogAgent(NativeAgent):
    """Security monitoring agent. Watches all traffic, logs anomalies."""
    
    def __init__(self, mqtt_host="localhost", mqtt_port=1883,
                 mqtt_user=None, mqtt_pass=None):
        super().__init__(
            name="watchdog", agent_id=0xDA7CD06E,
            mqtt_host=mqtt_host, mqtt_port=mqtt_port,
            mqtt_user=mqtt_user, mqtt_pass=mqtt_pass,
            channels=["general", "ai-chat", "council", "votes", "system"],
        )
        self.frame_log = []
        self.alerts = []
    
    def on_frame(self, frame, topic):
        sender = frame.get("agent_name", "unknown")
        text = frame.get("payload_text", "")
        
        entry = {
            "ts": time.time(),
            "sender": sender,
            "topic": topic,
            "type": frame.get("frame_type"),
            "intent": frame.get("intent"),
            "signed": frame.get("signed", False),
            "len": len(text),
        }
        self.frame_log.append(entry)
        
        # Alert on unsigned frames in production
        if not frame.get("signed") and frame.get("version", 1) >= 2:
            alert = f"⚠️ Unsigned v2 frame from {sender} on {topic}"
            self.alerts.append(alert)
            log.warning(alert)
        
        # Alert on rapid-fire from single agent
        recent = [e for e in self.frame_log[-20:] 
                  if e["sender"] == sender and time.time() - e["ts"] < 10]
        if len(recent) > 10:
            alert = f"🚨 Flood detected: {sender} sent {len(recent)} frames in 10s"
            self.alerts.append(alert)
            log.error(alert)
        
        # Log
        signed_icon = "🔏" if frame.get("signed") else "  "
        log.info(f"{signed_icon} [{sender}] {frame.get('frame_type')}/{frame.get('intent')} "
                 f"conf={frame.get('confidence', 0):.2f} | {text[:60]}")


# Fix: WatchdogAgent agent_id can't use hex literal with letters in it
WatchdogAgent.__init__.__defaults__ = ("localhost", 1883, None, None)


def run_native_agent(name="native-test", handler=None, **kwargs):
    """Quick-start a native agent."""
    agent = NativeAgent(name=name, handler=handler, **kwargs)
    try:
        agent.run()
    except KeyboardInterrupt:
        s = agent.stats()
        log.info(f"📊 {s['name']}: {s['messages_sent']} sent, "
                 f"{s['verified_frames']} verified, "
                 f"{s['unverified_frames']} unverified")


if __name__ == "__main__":
    import os
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')
    
    def echo_handler(frame, topic, verified):
        """Simple echo that only responds to verified frames."""
        if not verified:
            return None  # Ignore unsigned
        return f"[native-echo] Verified from {frame['agent_name']}: {frame['payload_text'][:100]}"
    
    run_native_agent(
        name="native-echo",
        mqtt_host=os.environ.get("MQTT_HOST", "localhost"),
        mqtt_user=os.environ.get("MQTT_USER", "bridge"),
        mqtt_pass=os.environ.get("MQTT_PASS", "thoughtwire_bridge_2026"),
        handler=echo_handler,
    )
