"""Tests for Thoughtwire frame signing."""
import pytest
from thoughtwire.protocol import encode
from thoughtwire.signing import (
    AgentKeyPair, sign_frame, verify_frame,
    generate_agent_keys, load_agent_keys, init_all_keys, list_keys,
)


@pytest.fixture(autouse=True)
def temp_keys_dir(monkeypatch, tmp_path):
    """Use temp directory for keys during tests."""
    import thoughtwire.signing as signing_mod
    monkeypatch.setattr(signing_mod, "KEYS_DIR", tmp_path)
    return tmp_path


class TestKeyPair:
    def test_generate_and_sign(self):
        kp = AgentKeyPair("test")
        kp.generate()
        assert kp.has_keys

        data = b"hello world"
        sig = kp.sign(data)
        assert len(sig) == 64  # Ed25519
        assert kp.verify(data, sig)

    def test_wrong_data_fails(self):
        kp = AgentKeyPair("test")
        kp.generate()
        sig = kp.sign(b"original")
        assert not kp.verify(b"tampered", sig)

    def test_wrong_key_fails(self):
        kp1 = AgentKeyPair("alice")
        kp1.generate()
        kp2 = AgentKeyPair("bob")
        kp2.generate()

        sig = kp1.sign(b"message")
        assert not kp2.verify(b"message", sig)

    def test_empty_signature_fails(self):
        kp = AgentKeyPair("test")
        kp.generate()
        assert not kp.verify(b"data", b"")

    def test_save_load_roundtrip(self, temp_keys_dir):
        kp = AgentKeyPair("roundtrip")
        kp.generate()
        kp.save()

        kp2 = AgentKeyPair("roundtrip")
        assert kp2.load()
        assert kp2.has_keys

        # Verify signature from original key
        data = b"test data"
        sig = kp.sign(data)
        assert kp2.verify(data, sig)

    def test_public_hex(self):
        kp = AgentKeyPair("hextest")
        kp.generate()
        hexkey = kp.public_hex
        assert len(hexkey) == 64  # 32 bytes = 64 hex chars

    def test_no_keys(self):
        kp = AgentKeyPair("empty")
        assert not kp.has_keys
        assert kp.sign(b"data") == b""
        assert not kp.verify(b"data", b"sig")
        assert kp.public_hex == "(no key)"


class TestFrameSigning:
    def test_sign_and_verify(self):
        kp = AgentKeyPair("signer")
        kp.generate()

        v1 = encode("vote", 0xC01FF43E, 0.87, "approve", b"yes")
        v2 = sign_frame(v1, kp)

        assert len(v2) == len(v1) + 2 + 64  # +2 header, +64 sig
        assert v2[0] == 2  # version 2

        decoded, verified, signed = verify_frame(v2, kp)
        assert signed is True
        assert verified is True
        assert decoded["frame_type"] == "vote"
        assert decoded["intent"] == "approve"

    def test_wrong_key_verification(self):
        kp1 = AgentKeyPair("alice")
        kp1.generate()
        kp2 = AgentKeyPair("bob")
        kp2.generate()

        v1 = encode("chat", 0, 1.0, "inform", b"secret")
        v2 = sign_frame(v1, kp1)

        _, verified, signed = verify_frame(v2, kp2)
        assert signed is True
        assert verified is False

    def test_unsigned_v1(self):
        kp = AgentKeyPair("any")
        kp.generate()

        v1 = encode("chat", 0, 1.0, "inform", b"unsigned")
        decoded, verified, signed = verify_frame(v1, kp)
        assert signed is False
        assert verified is False
        assert decoded is not None

    def test_too_short(self):
        kp = AgentKeyPair("any")
        decoded, verified, signed = verify_frame(b"\x00" * 5, kp)
        assert decoded is None

    def test_size_overhead(self):
        kp = AgentKeyPair("size")
        kp.generate()

        for payload in [b"", b"x", b"x" * 100, b"x" * 1000]:
            v1 = encode("chat", 0, 1.0, "inform", payload)
            v2 = sign_frame(v1, kp)
            overhead = len(v2) - len(v1)
            assert overhead == 66  # Always 2 + 64


class TestKeyManagement:
    def test_generate_agent_keys(self, temp_keys_dir):
        kp = generate_agent_keys("newagent")
        assert kp.has_keys
        assert (temp_keys_dir / "newagent.key").exists()
        assert (temp_keys_dir / "newagent.pub").exists()

    def test_load_nonexistent(self):
        kp = load_agent_keys("doesnotexist")
        assert not kp.has_keys

    def test_init_all_keys(self, temp_keys_dir):
        keys = init_all_keys(["a", "b", "c"])
        assert len(keys) == 3
        for name, kp in keys.items():
            assert kp.has_keys

        # Second call should load, not regenerate
        keys2 = init_all_keys(["a", "b", "c"])
        for name in keys:
            sig = keys[name].sign(b"test")
            assert keys2[name].verify(b"test", sig)

    def test_list_keys(self, temp_keys_dir):
        generate_agent_keys("alpha")
        generate_agent_keys("beta")
        keys = list_keys()
        assert "alpha" in keys
        assert "beta" in keys
