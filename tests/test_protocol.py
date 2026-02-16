"""Tests for Thoughtwire protocol encoding/decoding."""
import pytest
from thoughtwire.protocol import (
    encode, decode, FRAME_TYPES, INTENTS, AGENTS,
    validate_channel, validate_payload, ValidationError,
    frame_size_comparison, VERSION_1, VERSION_2,
    MAX_PAYLOAD, from_egregore_json, to_egregore_json,
)


class TestEncode:
    def test_basic_encode(self):
        frame = encode("chat", 0xC01FF43E, 0.5, "inform", b"hello")
        assert len(frame) == 14 + 5
        assert frame[0] == VERSION_1

    def test_empty_payload(self):
        frame = encode("heartbeat", 0, 1.0, "inform")
        assert len(frame) == 14

    def test_all_frame_types(self):
        for ft in FRAME_TYPES:
            frame = encode(ft, 0, 0.5, "inform", b"x")
            decoded = decode(frame)
            assert decoded["frame_type"] == ft

    def test_all_intents(self):
        for intent in INTENTS:
            frame = encode("chat", 0, 0.5, intent, b"x")
            decoded = decode(frame)
            assert decoded["intent"] == intent

    def test_confidence_mapping(self):
        for conf in [0.0, 0.25, 0.5, 0.75, 1.0]:
            frame = encode("chat", 0, conf, "inform")
            decoded = decode(frame)
            assert abs(decoded["confidence"] - conf) < 0.01

    def test_confidence_clamp(self):
        frame = encode("chat", 0, 1.5, "inform")
        decoded = decode(frame)
        assert decoded["confidence"] == 1.0

        frame = encode("chat", 0, -0.5, "inform")
        decoded = decode(frame)
        assert decoded["confidence"] == 0.0

    def test_v2_encode(self):
        frame = encode("chat", 0, 0.5, "inform", b"hello", version=VERSION_2)
        assert len(frame) == 16 + 5  # v2 header + payload
        assert frame[0] == VERSION_2


class TestDecode:
    def test_roundtrip(self):
        for text in [b"", b"hello", b"x" * 1000, "日本語".encode()]:
            frame = encode("chat", 0xDEADBEEF, 0.87, "propose", text)
            decoded = decode(frame)
            assert decoded is not None
            assert decoded["payload"] == text
            assert decoded["agent_id"] == 0xDEADBEEF
            assert decoded["frame_type"] == "chat"
            assert decoded["intent"] == "propose"

    def test_too_short(self):
        assert decode(b"") is None
        assert decode(b"\x00" * 13) is None

    def test_agent_name_lookup(self):
        frame = encode("chat", 0xC01FF43E, 1.0, "inform", b"hi")
        decoded = decode(frame)
        assert decoded["agent_name"] in ("nix", "llama")  # same id, dict ordering

    def test_unknown_agent(self):
        frame = encode("chat", 0x12345678, 1.0, "inform", b"hi")
        decoded = decode(frame)
        assert "12345678" in decoded["agent_name"].upper()

    def test_payload_text_utf8(self):
        text = "Hello 🌀 world"
        frame = encode("chat", 0, 1.0, "inform", text.encode("utf-8"))
        decoded = decode(frame)
        assert decoded["payload_text"] == text

    def test_signed_field_v1(self):
        frame = encode("chat", 0, 1.0, "inform", b"test")
        decoded = decode(frame)
        assert decoded["signed"] is False
        assert decoded["verified"] is False


class TestValidation:
    def test_valid_channels(self):
        for name in ["general", "ai-chat", "test_123", "a"]:
            assert validate_channel(name) == name

    def test_invalid_channels(self):
        for name in ["", "../etc/passwd", "a" * 65, "-start", " spaces"]:
            with pytest.raises(ValidationError):
                validate_channel(name)

    def test_payload_size_limit(self):
        validate_payload(b"x" * MAX_PAYLOAD)  # Should not raise
        with pytest.raises(ValidationError):
            validate_payload(b"x" * (MAX_PAYLOAD + 1))


class TestJsonConversion:
    def test_from_egregore(self):
        ejson = {"agent_id": "c01ff43e12345678", "payload": {"text": "hello"}}
        binary = from_egregore_json(ejson)
        decoded = decode(binary)
        assert decoded["payload_text"] == "hello"
        assert decoded["agent_id"] == 0xC01FF43E

    def test_to_egregore(self):
        frame = encode("chat", 0, 1.0, "inform", b"test")
        decoded = decode(frame)
        ejson = to_egregore_json(decoded, "general")
        assert ejson["channel"] == "general"
        assert ejson["payload"]["text"] == "test"

    def test_size_comparison(self):
        comp = frame_size_comparison("hello")
        assert comp["binary_bytes"] < comp["json_bytes"]
        assert comp["reduction_pct"] > 0
        assert comp["saved_bytes"] > 0
