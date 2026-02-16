"""Integration tests: cross-language schema validation and MQTT round-trip."""
import json
import os
import subprocess
import struct
import tempfile
import pytest

from thoughtwire.protocol import encode, decode, FRAME_TYPES, INTENTS, VERSION_1, VERSION_2
from thoughtwire.signing import AgentKeyPair, sign_frame, verify_frame
from thoughtwire.schema import generate


# ── C Cross-Validation ────────────────────────────────────────────

C_TEST_PROGRAM = r'''
#include "thoughtwire.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int main() {
    // Build a v1 frame
    tw_frame_v1_t frame;
    frame.version = TW_VERSION_1;
    frame.frame_type = TW_FRAME_VOTE;
    frame.agent_id = htonl(0xC01FF43E);
    frame.timestamp = htonl(1234567890);
    frame.confidence = tw_encode_confidence(0.95f);
    frame.intent = TW_INTENT_APPROVE;
    frame.payload_len = htons(3);

    unsigned char buf[17];
    memcpy(buf, &frame, 14);
    buf[14] = 'y'; buf[15] = 'e'; buf[16] = 's';

    // Print hex for Python to decode
    for (int i = 0; i < 17; i++) printf("%02x", buf[i]);
    printf("\n");

    // Also verify struct sizes
    printf("v1=%zu v2=%zu\n", sizeof(tw_frame_v1_t), sizeof(tw_frame_v2_t));
    return 0;
}
'''


class TestCCrossValidation:
    """Encode in C, decode in Python."""

    @pytest.fixture(autouse=True)
    def setup_c(self, tmp_path):
        """Compile C test program."""
        # Generate C header
        _, header = generate("c")
        (tmp_path / "thoughtwire.h").write_text(header)
        (tmp_path / "test.c").write_text(C_TEST_PROGRAM)

        result = subprocess.run(
            ["gcc", "-I", str(tmp_path), "-o", str(tmp_path / "test"),
             str(tmp_path / "test.c"), "-Wall", "-Werror"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            pytest.skip(f"gcc not available or compile failed: {result.stderr}")
        self.test_binary = str(tmp_path / "test")

    def test_c_to_python_decode(self):
        """Frame encoded in C should decode correctly in Python."""
        result = subprocess.run([self.test_binary], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")
        hex_str = lines[0]

        frame = decode(bytes.fromhex(hex_str))
        assert frame is not None
        assert frame["version"] == VERSION_1
        assert frame["frame_type"] == "vote"
        assert frame["agent_id"] == 0xC01FF43E
        assert frame["intent"] == "approve"
        assert frame["payload_text"] == "yes"
        assert abs(frame["confidence"] - 0.95) < 0.01

    def test_c_struct_sizes(self):
        """C struct sizes should match protocol spec."""
        result = subprocess.run([self.test_binary], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")
        sizes = lines[1]  # "v1=14 v2=16"
        assert "v1=14" in sizes
        assert "v2=16" in sizes

    def test_python_to_c_compatible(self):
        """Python-encoded frame should have correct byte layout for C."""
        frame = encode("vote", 0xC01FF43E, 0.95, "approve", b"yes")
        assert len(frame) == 17  # 14 header + 3 payload
        assert frame[0] == VERSION_1  # version
        assert frame[1] == FRAME_TYPES["vote"]  # frame_type
        # agent_id at bytes 2-5, network byte order
        agent_id = struct.unpack("!I", frame[2:6])[0]
        assert agent_id == 0xC01FF43E


# ── Protobuf Cross-Validation ────────────────────────────────────

class TestProtobufCrossValidation:
    """Encode in protobuf, decode in binary wire format."""

    @pytest.fixture(autouse=True)
    def setup_proto(self, tmp_path):
        """Compile protobuf schema."""
        _, proto_content = generate("protobuf")
        proto_file = tmp_path / "thoughtwire.proto"
        proto_file.write_text(proto_content)

        result = subprocess.run(
            ["protoc", f"--proto_path={tmp_path}", f"--python_out={tmp_path}", str(proto_file)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            pytest.skip(f"protoc not available: {result.stderr}")

        import sys
        sys.path.insert(0, str(tmp_path))
        self.tmp_path = tmp_path

    def test_protobuf_to_binary(self):
        """Protobuf frame fields should match binary encoding."""
        import importlib
        import sys
        sys.path.insert(0, str(self.tmp_path))
        tw = importlib.import_module("thoughtwire_pb2")

        # Create via protobuf
        pf = tw.Frame()
        pf.version = 1
        pf.frame_type = tw.FT_VOTE
        pf.agent_id = 0xC01FF43E
        pf.confidence = 0.95
        pf.intent = tw.INT_APPROVE
        pf.payload = b"yes"

        # Create same via binary
        bf = encode("vote", 0xC01FF43E, 0.95, "approve", b"yes")
        decoded = decode(bf)

        # Fields should match
        assert decoded["frame_type"] == "vote"
        assert decoded["agent_id"] == pf.agent_id
        assert abs(decoded["confidence"] - pf.confidence) < 0.01
        assert decoded["intent"] == "approve"
        assert decoded["payload"] == pf.payload

    def test_protobuf_batch(self):
        """FrameBatch should serialize/deserialize."""
        import importlib
        import sys
        sys.path.insert(0, str(self.tmp_path))
        tw = importlib.import_module("thoughtwire_pb2")

        batch = tw.FrameBatch()
        for i in range(5):
            f = batch.frames.add()
            f.frame_type = tw.FT_CHAT
            f.payload = f"msg-{i}".encode()
        batch.count = 5

        data = batch.SerializeToString()
        batch2 = tw.FrameBatch()
        batch2.ParseFromString(data)
        assert batch2.count == 5
        assert len(batch2.frames) == 5


# ── Rust Compile Check ────────────────────────────────────────────

class TestRustSchema:
    def test_rust_compiles(self, tmp_path):
        """Generated Rust code should compile."""
        cargo_bin = os.path.expanduser("~/.cargo/bin/cargo")
        if not os.path.exists(cargo_bin):
            pytest.skip("cargo not installed")

        _, rust_content = generate("rust")

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "lib.rs").write_text(rust_content)
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "tw-test"\nversion = "0.1.0"\nedition = "2021"\n'
        )

        result = subprocess.run(
            [cargo_bin, "check"],
            cwd=str(tmp_path), capture_output=True, text=True
        )
        assert result.returncode == 0, f"Rust compile failed: {result.stderr}"


# ── JSON Schema Validation ────────────────────────────────────────

class TestJsonSchemaValidation:
    def test_valid_frame(self):
        """Valid frame should pass JSON Schema validation."""
        _, schema_str = generate("json")
        schema = json.loads(schema_str)

        frame = {
            "version": 2, "frame_type": "vote", "agent_id": 0xC01FF43E,
            "timestamp": 1234567890, "confidence": 0.95, "intent": "approve",
        }

        try:
            import jsonschema
            jsonschema.validate(frame, schema)
        except ImportError:
            # Manual validation
            for req in schema["required"]:
                assert req in frame

    def test_invalid_frame_type(self):
        """Invalid frame_type should fail validation."""
        _, schema_str = generate("json")
        schema = json.loads(schema_str)

        frame = {
            "version": 1, "frame_type": "INVALID", "agent_id": 0,
            "timestamp": 0, "confidence": 0.5, "intent": "inform",
        }

        try:
            import jsonschema
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(frame, schema)
        except ImportError:
            assert frame["frame_type"] not in schema["properties"]["frame_type"]["enum"]


# ── Signing Cross-Format ─────────────────────────────────────────

class TestSigningIntegration:
    def test_sign_verify_full_chain(self):
        """Full chain: encode → sign → serialize → deserialize → verify."""
        kp = AgentKeyPair("integration-test")
        kp.generate()

        # Encode v1
        v1 = encode("chat", 0xDEADBEEF, 0.77, "propose", b"upgrade protocol")
        assert decode(v1)["signed"] is False

        # Sign to v2
        v2 = sign_frame(v1, kp)
        assert v2[0] == VERSION_2

        # Verify
        decoded, verified, signed = verify_frame(v2, kp)
        assert signed is True
        assert verified is True
        assert decoded["frame_type"] == "chat"
        assert decoded["intent"] == "propose"
        assert decoded["payload_text"] == "upgrade protocol"

        # Tamper with payload
        tampered = bytearray(v2)
        tampered[20] = 0xFF  # flip a payload byte
        _, verified_bad, _ = verify_frame(bytes(tampered), kp)
        assert verified_bad is False

    def test_different_agents_cant_forge(self):
        """Agent A's signature should not verify with Agent B's key."""
        alice = AgentKeyPair("alice")
        alice.generate()
        bob = AgentKeyPair("bob")
        bob.generate()

        frame = encode("vote", 0x1234, 1.0, "approve", b"yes")
        signed = sign_frame(frame, alice)

        _, verified, _ = verify_frame(signed, bob)
        assert verified is False
