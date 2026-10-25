"""Tests for deusproof-verify. No network: real receipts from a production record, plus synthetic
records signed here to prove each check also catches forgeries."""
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from deusproof_verify import checks
from deusproof_verify.cli import verify_bundle

VECTORS = Path(__file__).parent / "vectors"
BUNDLE = json.loads((VECTORS / "bundle_3c54818a.json").read_text(encoding="utf-8"))
# Block 971659 as printed by https://blockstream.info/api (RPC byte order), read on 19 Oct 2026.
BLOCK_971659_MERKLE_ROOT = "eebcbdc44a8f1edb2fe2279ce4d6e23b8b4277bdeeee2e2e47c84973f772e658"


def _did(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    data = b"\xed\x01" + raw
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = checks._B58[r] + out
    return "did:key:z" + "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


# ── real receipts ───────────────────────────────────────────────────────────

def _seed():
    return base64.b64decode(BUNDLE["seed_b64"])


def test_the_real_seed_matches_the_record():
    assert checks.check_seed(_seed(), BUNDLE["record"]).ok is True


def test_the_real_rfc3161_token_verifies_and_rejects_another_seed():
    tsr = base64.b64decode(BUNDLE["tsr_b64"])
    good = checks.check_rfc3161(tsr, _seed())
    assert good.ok is True and good.facts["tsa"] == "www.freetsa.org"
    assert checks.check_rfc3161(tsr, b"another seed").ok is False


def test_the_real_ots_reaches_the_real_bitcoin_block():
    first, blocks, _ = checks.ots_attestations(base64.b64decode(BUNDLE["ots_b64"]), _seed())
    heights = dict(blocks)
    assert 971659 in heights
    assert checks.check_bitcoin_root(heights[971659], BLOCK_971659_MERKLE_ROOT, 971659, "test").ok is True
    wrong = "00" * 32
    assert checks.check_bitcoin_root(heights[971659], wrong, 971659, "test").ok is False


def test_the_real_manifest_is_signed_by_a_registry_key():
    rec = BUNDLE["record"]
    dids = [h["did"] for h in BUNDLE["issuer"]["history"]]
    assert checks.check_manifest(rec["c2pa_manifest"], rec["signature_b64"], rec["manifest_hash"], dids).ok is True
    tampered = copy.deepcopy(rec["c2pa_manifest"])
    tampered["title"] = "something else"
    assert checks.check_manifest(tampered, rec["signature_b64"], "", dids).ok is False


def test_the_real_inclusion_proof_reaches_its_root():
    inc = BUNDLE["inclusion"]
    assert checks.check_inclusion(inc["entry_hash"], inc["proof"], inc["merkle_root"]).ok is True
    assert checks.check_inclusion("00" * 32, inc["proof"], inc["merkle_root"]).ok is False


def test_the_whole_real_bundle_passes_without_network():
    results = verify_bundle(BUNDLE, [], None, explorer=None)
    assert not [r for r in results if r.ok is False], [(r.name, r.detail) for r in results]
    # Everything but the Bitcoin header (which needs one explorer read) is checked offline.
    passed = {r.name for r in results if r.ok is True}
    assert {"sealed seed", "manifest signature", "ledger entry", "Merkle inclusion", "signed checkpoint",
            "RFC 3161 timestamp"} <= passed, passed


# ── synthetic: what a forger cannot get past ────────────────────────────────

def test_checkpoint_signature_needs_a_trusted_key():
    registry, stranger = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    root, size = "ab" * 32, 10
    sig = base64.b64encode(registry.sign(f"{root}:{size}".encode())).decode()
    assert checks.check_checkpoint(root, size, sig, [_did(registry)]).ok is True
    assert checks.check_checkpoint(root, size + 1, sig, [_did(registry)]).ok is False
    assert checks.check_checkpoint(root, size, sig, [_did(stranger)]).ok is False


def test_entry_preimage_must_hash_and_match_the_record():
    rec = {"id": "c1", "output_hash": "aa" * 32, "agent_did": "did:key:zX", "platform": "mcp"}
    pre = {"prev_hash": "00" * 32, "certification_id": "c1", "agent_did": "did:key:zX", "platform": "mcp",
           "output_hash": "aa" * 32, "created_at": "2026-10-19T00:00:00+00:00"}
    h = hashlib.sha256(json.dumps(pre, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert checks.check_entry(pre, h, rec).ok is True
    assert checks.check_entry(dict(pre, output_hash="bb" * 32), h, rec).ok is False
    assert checks.check_entry(pre, "cc" * 32, rec).ok is False


def test_a_file_that_is_not_the_one_sealed_fails():
    rec = BUNDLE["record"]
    assert checks.check_seed(_seed(), rec, file_sha256="ff" * 32).ok is False
    assert checks.check_seed(_seed(), rec, file_sha256=rec["output_hash"]).ok is True
