"""Conformance gate: reproduce the golden vectors (generated from the deployed
rust-pois implementation) byte-for-byte. Same contract the Rust crate and C++
SDK pass; this is what makes the Python SDK a real implementation of SESAME.
"""

import json
from pathlib import Path

from sesame import canonical, tier1, tier3

VEC = Path(__file__).resolve().parents[2] / "test-vectors"


def _load(name):
    return json.loads((VEC / name).read_text())


def test_tier1_request_vectors_reproduce():
    vectors = _load("tier1.json")["request_vectors"]
    assert vectors
    for v in vectors:
        body = bytes.fromhex(v["body_hex"])
        body_hash = canonical.body_hash_hex(body)
        canon = canonical.request_canonical(
            v["method"], v["path"], v["timestamp"], v["nonce"], body_hash, v["scope"]
        )
        assert canon == v["expected_canonical"], v["name"]
        key = bytes.fromhex(v["signing_key_hex"])
        assert tier1.sign(key, canon) == v["expected_signature_hex"], v["name"]


def test_tier1_response_vectors_reproduce():
    vectors = _load("tier1.json")["response_vectors"]
    assert vectors
    for v in vectors:
        body = bytes.fromhex(v["body_hex"])
        body_hash = canonical.body_hash_hex(body)
        canon = canonical.response_canonical(
            v["correlation"], v["timestamp"], v["nonce"], body_hash, v["scope"]
        )
        assert canon == v["expected_canonical"], v["name"]
        key = bytes.fromhex(v["signing_key_hex"])
        assert tier1.sign(key, canon) == v["expected_signature_hex"], v["name"]


def test_tier3_aead_vectors_reproduce():
    vectors = _load("tier3.json")["aead_vectors"]
    assert vectors
    for v in vectors:
        aad = tier3.aad_for_headers(
            v["version"], v["key_id"], v["timestamp"], v["nonce"], v["scope"]
        )
        assert aad.decode("utf-8") == v["expected_aad_utf8"], v["name"]
        key = bytes.fromhex(v["enc_key_hex"])
        iv = bytes.fromhex(v["iv_hex"])
        plaintext = bytes.fromhex(v["plaintext_hex"])
        body = tier3.seal(key, iv, aad, plaintext)
        assert body.hex() == v["expected_body_hex"], v["name"]
        assert tier3.open(key, iv, aad, body) == plaintext, v["name"]
