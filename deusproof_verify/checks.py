"""Offline checks for DEUSPROOF records.

Every function here works on bytes and strings you already hold. None of them talks to DEUSPROOF.
They reproduce, independently, what the registry claims about a record:

  * the manifest signature (Ed25519, under the registry's did:key);
  * the ledger entry hash (sha256 of a canonical JSON preimage);
  * the Merkle inclusion of that entry in a signed checkpoint;
  * the RFC 3161 timestamp token from an independent timestamp authority;
  * the OpenTimestamps proof, down to a Bitcoin block's Merkle root.

Each check returns a Result. A failed check says what did not match; it never raises for bad input.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


@dataclass
class Result:
    name: str
    ok: bool | None  # None = could not be checked (missing data), never "passed"
    detail: str = ""
    facts: dict = field(default_factory=dict)


# ── identifiers and canonical bytes ─────────────────────────────────────────


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def did_key_public_key(did: str) -> Ed25519PublicKey:
    """did:key:z… (base58btc, Ed25519 multicodec 0xed01) → public key."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a base58btc did:key: {did}")
    decoded = b58decode(did[len("did:key:z"):])
    if decoded[:2] != _ED25519_MULTICODEC:
        raise ValueError("did:key is not Ed25519")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def canonical(obj) -> bytes:
    """The registry's canonical JSON: sorted keys, no spaces, ASCII escapes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _ed25519_ok(did: str, payload: bytes, signature: bytes) -> bool:
    try:
        did_key_public_key(did).verify(signature, payload)
        return True
    except (InvalidSignature, ValueError):
        return False


# ── the manifest ────────────────────────────────────────────────────────────


def check_manifest(manifest: dict, signature_b64: str, manifest_hash: str, trusted_dids: list[str]) -> Result:
    if not manifest or not signature_b64:
        return Result("manifest signature", None, "the record carries no signed manifest")
    payload = canonical(manifest)
    issuer = (manifest.get("signature_info") or {}).get("issuer", "")
    facts = {"issuer": issuer}
    if manifest_hash and hashlib.sha256(payload).hexdigest() != manifest_hash:
        return Result("manifest signature", False, "the manifest does not hash to manifest_hash", facts)
    if trusted_dids and issuer not in trusted_dids:
        return Result("manifest signature", False, f"issuer {issuer} is not one of the registry keys you trust", facts)
    if not _ed25519_ok(issuer, payload, base64.b64decode(signature_b64)):
        return Result("manifest signature", False, "Ed25519 signature does not verify", facts)
    return Result("manifest signature", True, f"signed by {issuer}", facts)


# ── the ledger: entry, inclusion, checkpoint ────────────────────────────────


def entry_hash(preimage: dict) -> str:
    return hashlib.sha256(canonical(preimage)).hexdigest()


def check_entry(preimage: dict | None, expected_entry_hash: str | None, record: dict) -> Result:
    if not preimage or not expected_entry_hash:
        return Result("ledger entry", None, "the server did not publish the entry preimage")
    for k_pre, k_rec in (("certification_id", "id"), ("output_hash", "output_hash"),
                         ("agent_did", "agent_did"), ("platform", "platform")):
        if str(preimage.get(k_pre, "")) != str(record.get(k_rec, "")):
            return Result("ledger entry", False, f"entry field {k_pre} does not match the record")
    got = entry_hash(preimage)
    if got != expected_entry_hash:
        return Result("ledger entry", False, f"preimage hashes to {got}, not {expected_entry_hash}")
    return Result("ledger entry", True, "the entry hash commits to this record's id, agent and fingerprint",
                  {"entry_hash": got, "entry_time": preimage.get("created_at", "")})


def leaf_hash(entry_hash_hex: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(entry_hash_hex)).digest()


def check_inclusion(entry_hash_hex: str, proof: list[dict], root_hex: str) -> Result:
    if not entry_hash_hex or root_hex is None:
        return Result("Merkle inclusion", None, "no inclusion proof available")
    acc = leaf_hash(entry_hash_hex)
    for step in proof or []:
        sibling = bytes.fromhex(step["hash"])
        if step.get("position") == "left":
            acc = hashlib.sha256(NODE_PREFIX + sibling + acc).digest()
        else:
            acc = hashlib.sha256(NODE_PREFIX + acc + sibling).digest()
    if acc.hex() != root_hex:
        return Result("Merkle inclusion", False, "the audit path does not lead to the checkpoint root")
    return Result("Merkle inclusion", True, f"entry is in the tree with root {root_hex[:16]}...")


def check_checkpoint(root_hex: str, tree_size: int, signature_b64: str | None, trusted_dids: list[str]) -> Result:
    if not signature_b64:
        return Result("signed checkpoint", None, "no checkpoint covers this entry yet")
    payload = f"{root_hex}:{tree_size}".encode("utf-8")
    sig = base64.b64decode(signature_b64)
    for did in trusted_dids:
        if _ed25519_ok(did, payload, sig):
            return Result("signed checkpoint", True, f"root and size {tree_size} signed by {did}", {"signer": did})
    return Result("signed checkpoint", False, "no trusted registry key signed this root and size")


# ── the seed both timestamps cover ──────────────────────────────────────────


def seed_bytes(record: dict) -> bytes:
    return f"{record.get('prompt_hash', '')}:{record.get('output_hash', '')}:{record.get('id', '')}".encode("utf-8")


def check_seed(seed: bytes, record: dict, file_sha256: str | None = None) -> Result:
    if seed != seed_bytes(record):
        return Result("sealed seed", False, "the downloaded seed is not prompt_hash:output_hash:id of this record")
    if file_sha256 and file_sha256 != record.get("output_hash"):
        return Result("sealed seed", False, "your file's SHA-256 is not the record's output_hash")
    extra = " and your file's SHA-256 matches it" if file_sha256 else ""
    return Result("sealed seed", True, f"seed is prompt_hash:output_hash:id{extra}")


# ── RFC 3161 ────────────────────────────────────────────────────────────────


def _hash_name(name: str):
    return {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512()}.get(name)


def check_rfc3161(tsr: bytes, seed: bytes) -> Result:
    """Parse the TimeStampResp, check the imprint is the seed's digest, and verify the CMS signature
    with the certificate the authority embedded. Trust in that certificate is yours to anchor."""
    from asn1crypto import tsp
    from cryptography import x509

    name = "RFC 3161 timestamp"
    try:
        resp = tsp.TimeStampResp.load(tsr)
        token = resp["time_stamp_token"]
        signed = token["content"]
        tst = signed["encap_content_info"]["content"].parsed
    except Exception as exc:  # noqa: BLE001
        return Result(name, False, f"unreadable token: {exc}")
    imprint_alg = tst["message_imprint"]["hash_algorithm"]["algorithm"].native
    imprint = tst["message_imprint"]["hashed_message"].native
    if hashlib.new(imprint_alg, seed).digest() != imprint:
        return Result(name, False, "the token does not timestamp this seed")
    gen_time = tst["gen_time"].native
    facts = {"time": gen_time.isoformat() if gen_time else "", "imprint_alg": imprint_alg}

    signer = signed["signer_infos"][0]
    certs = [c.chosen for c in (signed["certificates"] or [])]
    sid_choice = signer["sid"]
    if sid_choice.name == "issuer_and_serial_number":
        sid = sid_choice.chosen
        cert = next((c for c in certs
                     if c.issuer == sid["issuer"] and c.serial_number == sid["serial_number"].native), None)
    else:
        cert = certs[0] if certs else None
    if cert is None:
        return Result(name, None, "valid imprint, but the token carries no certificate to check the signature", facts)
    facts["tsa"] = cert.subject.native.get("common_name") or cert.subject.human_friendly

    digest_alg = signer["digest_algorithm"]["algorithm"].native
    content = signed["encap_content_info"]["content"].contents
    attrs = signer["signed_attrs"]
    md = next((a["values"][0].native for a in attrs if a["type"].native == "message_digest"), None)
    if md is None or hashlib.new(digest_alg, content).digest() != md:
        return Result(name, False, "the signed attributes do not match the token content", facts)
    to_verify = b"\x31" + attrs.dump()[1:]  # signed attributes are signed as a SET OF
    signature = signer["signature"].native
    pub = x509.load_der_x509_certificate(cert.dump()).public_key()
    halg = _hash_name(digest_alg)
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, to_verify, ec.ECDSA(halg))
        else:
            sig_alg = signer["signature_algorithm"]["algorithm"].native
            pad = (padding.PSS(mgf=padding.MGF1(halg), salt_length=padding.PSS.AUTO)
                   if sig_alg == "rsassa_pss" else padding.PKCS1v15())
            pub.verify(signature, to_verify, pad, halg)
    except InvalidSignature:
        return Result(name, False, "the authority's signature does not verify", facts)
    return Result(name, True, f"{facts['time']} by {facts['tsa']} (signature valid with the embedded certificate)",
                  facts)


# ── OpenTimestamps / Bitcoin ────────────────────────────────────────────────


def ots_attestations(ots: bytes, seed: bytes) -> tuple[Result, list[tuple[int, bytes]], list[str]]:
    """Read the .ots proof. Returns (result, [(block height, merkle-root msg)], [pending calendars])."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile

    name = "Bitcoin anchor"
    try:
        dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(ots))
    except Exception as exc:  # noqa: BLE001
        return Result(name, False, f"unreadable .ots: {exc}"), [], []
    if dtf.file_digest != hashlib.sha256(seed).digest():
        return Result(name, False, "the .ots proof is for a different file"), [], []
    blocks, pending = [], []
    for msg, att in dtf.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            blocks.append((att.height, msg))
        elif isinstance(att, PendingAttestation):
            uri = att.uri.decode() if isinstance(att.uri, bytes) else str(att.uri)
            pending.append(uri)
    if not blocks:
        return Result(name, None, "still pending in the calendars; download the .ots again later", {"pending": pending}), [], pending
    return Result(name, None, "attested in a Bitcoin block; checking the block header next"), blocks, pending


def check_bitcoin_root(msg: bytes, merkle_root_hex: str, height: int, source: str) -> Result:
    """Block explorers print the Merkle root byte-reversed (RPC order); the proof holds internal order."""
    if bytes.fromhex(merkle_root_hex)[::-1] != msg:
        return Result("Bitcoin anchor", False, f"block {height}'s Merkle root does not match the proof")
    return Result("Bitcoin anchor", True, f"committed in Bitcoin block {height} (header read from {source})",
                  {"height": height})
