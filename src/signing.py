"""
Thoughtwire Frame Signing — Ed25519 signatures for agent attestation.

Each agent has a keypair. Frames are signed with the private key.
Recipients verify with the public key. Unsigned frames are accepted
but marked as unverified.
"""

import hashlib
import hmac
import os
import json
import struct
from pathlib import Path

# Try Ed25519 via cryptography library, fall back to HMAC-SHA256
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False



# Import bridge components (handle both package and direct execution)
try:
    from .bridge import FRAME_HEADER, FRAME_TYPES_REV, INTENTS_REV, decode_frame
except ImportError:
    from bridge import FRAME_HEADER, FRAME_TYPES_REV, INTENTS_REV, decode_frame

KEYS_DIR = Path(os.environ.get("THOUGHTWIRE_KEYS", 
                                os.path.expanduser("~/.thoughtwire/keys")))


class AgentKeyPair:
    """Ed25519 keypair for an agent."""
    
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.private_key = None
        self.public_key = None
        self._hmac_secret = None  # Fallback
    
    def generate(self):
        """Generate a new keypair."""
        if HAS_ED25519:
            self.private_key = Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        else:
            # HMAC fallback: generate a 32-byte secret
            self._hmac_secret = os.urandom(32)
    
    def save(self):
        """Save keypair to disk."""
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        
        if HAS_ED25519 and self.private_key:
            priv_bytes = self.private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )
            pub_bytes = self.public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            (KEYS_DIR / f"{self.agent_name}.key").write_bytes(priv_bytes)
            (KEYS_DIR / f"{self.agent_name}.pub").write_bytes(pub_bytes)
            os.chmod(KEYS_DIR / f"{self.agent_name}.key", 0o600)
        elif self._hmac_secret:
            (KEYS_DIR / f"{self.agent_name}.hmac").write_bytes(self._hmac_secret)
            os.chmod(KEYS_DIR / f"{self.agent_name}.hmac", 0o600)
    
    def load(self) -> bool:
        """Load keypair from disk. Returns True if found."""
        if HAS_ED25519:
            priv_path = KEYS_DIR / f"{self.agent_name}.key"
            pub_path = KEYS_DIR / f"{self.agent_name}.pub"
            if priv_path.exists():
                priv_bytes = priv_path.read_bytes()
                self.private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
                self.public_key = self.private_key.public_key()
                return True
            elif pub_path.exists():
                pub_bytes = pub_path.read_bytes()
                self.public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
                return True
        
        hmac_path = KEYS_DIR / f"{self.agent_name}.hmac"
        if hmac_path.exists():
            self._hmac_secret = hmac_path.read_bytes()
            return True
        
        return False
    
    def sign(self, data: bytes) -> bytes:
        """Sign data. Returns signature bytes."""
        if HAS_ED25519 and self.private_key:
            return self.private_key.sign(data)  # 64 bytes
        elif self._hmac_secret:
            return hmac.new(self._hmac_secret, data, hashlib.sha256).digest()  # 32 bytes
        else:
            return b""  # No key = unsigned
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True if valid."""
        if not signature:
            return False
        
        if HAS_ED25519 and self.public_key:
            try:
                self.public_key.verify(signature, data)
                return True
            except Exception:
                return False
        elif self._hmac_secret:
            expected = hmac.new(self._hmac_secret, data, hashlib.sha256).digest()
            return hmac.compare_digest(signature, expected)
        
        return False


# ── V2 Frame Signing ─────────────────────────────────────────────

# V2 header: original 14 bytes + 2 bytes sig_len = 16 bytes
FRAME_V2_HEADER = struct.Struct("!BBIIBBhH")  # 16 bytes

def sign_frame(frame_v1: bytes, keypair: AgentKeyPair) -> bytes:
    """Take a v1 frame and produce a signed v2 frame.
    
    V2 layout: [v2 header 16B] [payload] [signature]
    """
    if len(frame_v1) < 14:
        return frame_v1
    
    # Parse v1 header
    version, ftype, agent_id, ts, conf, intent, plen = FRAME_HEADER.unpack(frame_v1[:14])
    payload = frame_v1[14:]
    
    # Sign the header + payload (everything except signature)
    signature = keypair.sign(frame_v1)
    sig_len = len(signature)
    
    # Build v2 header
    v2_header = FRAME_V2_HEADER.pack(2, ftype, agent_id, ts, conf, intent, plen, sig_len)
    
    return v2_header + payload + signature


def verify_frame(frame_v2: bytes, keypair: AgentKeyPair) -> tuple:
    """Verify a v2 signed frame.
    
    Returns: (decoded_dict, is_verified, is_signed)
    """
    if len(frame_v2) < 16:
        return None, False, False
    
    # Check version
    version = frame_v2[0]
    
    if version == 1:
        # V1 frame, unsigned
        decoded = decode_frame(frame_v2)
        if decoded:
            decoded["signed"] = False
            decoded["verified"] = False
        return decoded, False, False
    
    elif version == 2:
        # Parse v2 header
        ver, ftype, agent_id, ts, conf, intent, plen, sig_len = \
            FRAME_V2_HEADER.unpack(frame_v2[:16])
        
        payload = frame_v2[16:16+plen]
        signature = frame_v2[16+plen:16+plen+sig_len] if sig_len > 0 else b""
        
        # Reconstruct v1 frame for verification
        v1_header = FRAME_HEADER.pack(1, ftype, agent_id, ts, conf, intent, plen)
        v1_frame = v1_header + payload
        
        # Verify
        is_verified = keypair.verify(v1_frame, signature) if signature else False
        
        decoded = {
            "version": ver,
            "frame_type": FRAME_TYPES_REV.get(ftype, str(ftype)),
            "agent_id": agent_id,
            "timestamp": ts,
            "confidence": conf / 255.0,
            "intent": INTENTS_REV.get(intent, str(intent)),
            "payload": payload,
            "payload_text": payload.decode("utf-8", errors="replace") if payload else "",
            "signed": sig_len > 0,
            "verified": is_verified,
            "signature_len": sig_len,
        }
        
        return decoded, is_verified, sig_len > 0
    
    return None, False, False


# ── Key Management ────────────────────────────────────────────────

def generate_agent_keys(agent_name: str) -> AgentKeyPair:
    """Generate and save a new keypair for an agent."""
    kp = AgentKeyPair(agent_name)
    kp.generate()
    kp.save()
    return kp


def load_agent_keys(agent_name: str) -> AgentKeyPair:
    """Load existing keypair for an agent."""
    kp = AgentKeyPair(agent_name)
    kp.load()
    return kp


def init_all_keys(agents: list) -> dict:
    """Generate keys for all agents. Returns dict of name→keypair."""
    keys = {}
    for name in agents:
        kp = AgentKeyPair(name)
        if not kp.load():
            kp.generate()
            kp.save()
            print(f"  🔑 Generated keys for {name}")
        else:
            print(f"  🔑 Loaded existing keys for {name}")
        keys[name] = kp
    return keys


def export_public_keys() -> dict:
    """Export all public keys as hex strings for distribution."""
    pubkeys = {}
    if not KEYS_DIR.exists():
        return pubkeys
    
    for pub_file in KEYS_DIR.glob("*.pub"):
        name = pub_file.stem
        pubkeys[name] = pub_file.read_bytes().hex()
    
    for hmac_file in KEYS_DIR.glob("*.hmac"):
        name = hmac_file.stem
        pubkeys[name] = "(hmac-shared-secret)"
    
    return pubkeys
