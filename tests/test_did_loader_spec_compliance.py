"""
Tests for ic_candid_parser + DIDLoader Candid-spec compliance fixes.

Covers two issues found in the May-2026 Candid audit:

- #1  composite_query was serialized by the Rust parser as "compositequery"
      (Debug-formatter-derived, underscore dropped). The Rust side now uses
      an explicit match on FuncMode; the Python side normalizes any
      legacy "compositequery" tokens emitted by older PyPI wheels.

- #2  `import "path"` directives were silently dropped, leaving any
      referenced external types unresolved. The Rust parser now raises a
      ValueError with a clear message.
"""

from __future__ import annotations

import json
import pytest

from icp_candid.did_loader import DIDLoader, ic_candid_parser, _normalize_modes
from icp_candid.candid import Types, encode


# ===========================================================================
# #1: composite_query round-trips through the DID loader
# ===========================================================================

class TestCompositeQueryMode:
    """
    A DID file declaring composite_query must end up as the canonical
    'composite_query' token in the FuncClass, so that subsequent type-table
    encoding produces the spec-defined byte 0x03 (not the previous accidental
    fallback).
    """

    def test_parser_emits_canonical_token(self):
        """The Rust extension itself must emit 'composite_query' (with underscore)."""
        did = "service : { foo : () -> (nat) composite_query }"
        out = json.loads(ic_candid_parser.parse_did(did))
        modes = out["actor"]["methods"][0]["modes"]
        assert modes == ["composite_query"]

    def test_did_loader_yields_canonical_mode(self):
        """After loading via DIDLoader the FuncClass.modes is canonical."""
        loader = DIDLoader()
        res = loader.load_did_source(
            "service : { foo : () -> (nat) composite_query }"
        )
        foo = res["methods"]["foo"]
        assert foo.modes == ["composite_query"]

    def test_normalizer_fixes_legacy_token(self):
        """Even if a legacy wheel produced 'compositequery', _normalize_modes restores the canonical form."""
        assert _normalize_modes(["compositequery"]) == ["composite_query"]
        # Already-canonical tokens pass through unchanged.
        assert _normalize_modes(["query", "oneway", "composite_query"]) == [
            "query",
            "oneway",
            "composite_query",
        ]
        # Unknown tokens are NOT silently rewritten — they pass through so
        # downstream validation (candid.py FuncClass.encodeType) can reject them.
        assert _normalize_modes(["weird"]) == ["weird"]

    def test_func_type_with_composite_query_encodes(self):
        """
        Regression: with the canonical mode in place, the type encoder
        must produce the spec byte 0x03 instead of raising.
        """
        loader = DIDLoader()
        res = loader.load_did_source(
            "service : { foo : () -> (nat) composite_query }"
        )
        foo = res["methods"]["foo"]
        # Place the func type inside a record so its type table gets emitted.
        rec = Types.Record({"f": foo})
        wire = encode([{"type": rec, "value": {"f": [b"\x04", "m"]}}])
        # The mode byte 0x03 must appear somewhere in the type table region.
        # (The record itself is 0x6C; the func is 0x6A; the mode bytes are at
        # the tail of the func type entry.) A loose containment check is
        # sufficient for spec-conformance.
        assert b"\x03" in wire


# ===========================================================================
# #2: import directives raise a clear error
# ===========================================================================

class TestImportDirectiveRejected:
    """
    `import "path"` and `import service "path"` are valid Candid syntax,
    but the parser cannot resolve them (no filesystem access). Previously
    they were silently dropped; now they must raise.
    """

    def test_import_type_raises(self):
        did = 'import "./other.did"; service : { foo : () -> () }'
        with pytest.raises(ValueError, match="import directives are not supported"):
            ic_candid_parser.parse_did(did)

    def test_import_service_raises(self):
        did = 'import service "./other.did"; service : { foo : () -> () }'
        with pytest.raises(ValueError, match="import directives are not supported"):
            ic_candid_parser.parse_did(did)

    def test_did_loader_surfaces_the_error(self):
        """Errors from the Rust extension must propagate through load_did_source."""
        loader = DIDLoader()
        with pytest.raises(ValueError):
            loader.load_did_source('import "./x.did"; service : { f : () -> () }')

    def test_clean_did_still_works(self):
        """A DID file without imports must still parse cleanly."""
        loader = DIDLoader()
        res = loader.load_did_source(
            "type X = nat; service : { f : (X) -> (X) query }"
        )
        assert "f" in res["methods"]
        assert res["methods"]["f"].modes == ["query"]
