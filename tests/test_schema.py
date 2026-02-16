"""Tests for schema generation."""
import json
import pytest
from thoughtwire.schema import generate, FORMATS
from thoughtwire.protocol import FRAME_TYPES, INTENTS


class TestSchemaGeneration:
    @pytest.mark.parametrize("fmt", ["protobuf", "flatbuffers", "json", "c", "rust"])
    def test_generates_content(self, fmt):
        filename, content = generate(fmt)
        assert len(content) > 100
        assert filename.endswith((".proto", ".fbs", ".json", ".h", ".rs"))

    def test_protobuf_has_all_types(self):
        _, content = generate("protobuf")
        for ft in FRAME_TYPES:
            assert f"FT_{ft.upper()}" in content

    def test_protobuf_has_all_intents(self):
        _, content = generate("protobuf")
        for intent in INTENTS:
            assert f"INT_{intent.upper()}" in content

    def test_c_header_guards(self):
        _, content = generate("c")
        assert "#ifndef THOUGHTWIRE_H" in content
        assert "#endif" in content

    def test_c_has_structs(self):
        _, content = generate("c")
        assert "tw_frame_v1_t" in content
        assert "tw_frame_v2_t" in content

    def test_rust_has_enums(self):
        _, content = generate("rust")
        assert "pub enum FrameType" in content
        assert "pub enum Intent" in content
        assert "pub struct FrameV1Header" in content

    def test_json_schema_valid(self):
        _, content = generate("json")
        schema = json.loads(content)
        assert schema["$schema"].startswith("https://json-schema.org")
        assert "frame_type" in schema["properties"]
        assert set(FRAME_TYPES.keys()) == set(schema["properties"]["frame_type"]["enum"])

    def test_flatbuffers_has_tables(self):
        _, content = generate("flatbuffers")
        assert "table Frame" in content
        assert "enum FrameType" in content

    def test_unknown_format(self):
        with pytest.raises(ValueError):
            generate("xml")

    def test_aliases(self):
        """proto and protobuf should produce the same output."""
        _, c1 = generate("proto")
        _, c2 = generate("protobuf")
        # Content identical except possibly timestamp
        assert c1[:50] == c2[:50]
