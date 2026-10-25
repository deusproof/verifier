"""deusproof-verify — check a DEUSPROOF record yourself.

    deusproof-verify <certificate-id> [--file PATH] [--issuer did:key:…] [--save bundle.json]
    deusproof-verify --bundle bundle.json [--issuer did:key:…]

Online, it downloads the record and its receipts once (from deusproof.com, or --base), then does every
check locally. With --save you keep everything in one file; with --bundle you re-check it later with
no call to DEUSPROOF at all. The Bitcoin step reads one block header from a public explorer of your
choice (--explorer), or is skipped with --no-bitcoin.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request

from . import __version__, checks

# DEUSPROOF_VERIFY_UA lets the registry's own tests label themselves, so they are not counted as users.
UA = os.environ.get("DEUSPROOF_VERIFY_UA") or f"deusproof-verify/{__version__}"


def _get(url: str, as_json: bool = True):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:  # noqa: S310 — https URLs chosen by the user
        data = r.read()
    return json.loads(data) if as_json else data


def _get_optional(url: str, as_json: bool = True):
    try:
        return _get(url, as_json)
    except Exception:  # noqa: BLE001 — a missing receipt is reported, not fatal
        return None


def fetch_bundle(base: str, cert_id: str) -> dict:
    base = base.rstrip("/")
    seed = _get_optional(f"{base}/api/anchors/seed/{cert_id}", as_json=False)
    tsr = _get_optional(f"{base}/api/anchors/tsr/{cert_id}", as_json=False)
    ots = _get_optional(f"{base}/api/anchors/ots/{cert_id}", as_json=False)
    return {
        "format": "deusproof-verify-bundle/1",
        "source": base,
        "record": _get(f"{base}/api/verify/{cert_id}"),
        "inclusion": _get_optional(f"{base}/api/anchors/inclusion/{cert_id}"),
        "issuer": _get_optional(f"{base}/api/anchors/issuer"),
        "seed_b64": base64.b64encode(seed).decode() if seed else None,
        "tsr_b64": base64.b64encode(tsr).decode() if tsr else None,
        "ots_b64": base64.b64encode(ots).decode() if ots else None,
    }


def trusted_registry_dids(bundle: dict, pinned: list[str]) -> tuple[list[str], str]:
    if pinned:
        return pinned, "pinned by you"
    history = (bundle.get("issuer") or {}).get("history") or []
    dids = [h.get("did") for h in history if h.get("did")]
    return dids, "as published by the registry (pin one with --issuer to remove that trust)"


def verify_bundle(bundle: dict, pinned: list[str], file_sha256: str | None, explorer: str | None) -> list[checks.Result]:
    rec = bundle["record"]
    dids, _ = trusted_registry_dids(bundle, pinned)
    results: list[checks.Result] = []

    seed = base64.b64decode(bundle["seed_b64"]) if bundle.get("seed_b64") else None
    if seed is None:
        results.append(checks.Result("sealed seed", None, "no seed yet: the timestamps may still be settling"))
    else:
        results.append(checks.check_seed(seed, rec, file_sha256))

    results.append(checks.check_manifest(rec.get("c2pa_manifest") or {}, rec.get("signature_b64", ""),
                                         rec.get("manifest_hash", ""), dids))
    results.append(checks.check_entry(rec.get("ledger_entry_preimage"), rec.get("ledger_entry_hash"), rec))

    inc = bundle.get("inclusion") or {}
    if inc:
        if inc.get("entry_hash") != rec.get("ledger_entry_hash"):
            results.append(checks.Result("Merkle inclusion", False, "the proof is for a different ledger entry"))
        else:
            results.append(checks.check_inclusion(inc["entry_hash"], inc.get("proof") or [], inc.get("merkle_root")))
        results.append(checks.check_checkpoint(inc.get("merkle_root", ""), int(inc.get("tree_size") or 0),
                                               inc.get("checkpoint_signature_b64"), dids))
    else:
        results.append(checks.Result("Merkle inclusion", None, "no inclusion proof published yet"))

    if seed is not None and bundle.get("tsr_b64"):
        results.append(checks.check_rfc3161(base64.b64decode(bundle["tsr_b64"]), seed))
    else:
        results.append(checks.Result("RFC 3161 timestamp", None, "no timestamp token downloaded"))

    if seed is not None and bundle.get("ots_b64"):
        first, blocks, _ = checks.ots_attestations(base64.b64decode(bundle["ots_b64"]), seed)
        if not blocks or explorer is None:
            if blocks and explorer is None:
                first = checks.Result("Bitcoin anchor", None,
                                      f"attested in block {blocks[0][0]}; header not checked (--no-bitcoin)")
            results.append(first)
        else:
            height, msg = blocks[0]
            try:
                block_hash = _get(f"{explorer.rstrip('/')}/block-height/{height}", as_json=False).decode().strip()
                header = _get(f"{explorer.rstrip('/')}/block/{block_hash}")
                results.append(checks.check_bitcoin_root(msg, header["merkle_root"], height, explorer))
            except Exception as exc:  # noqa: BLE001
                results.append(checks.Result("Bitcoin anchor", None, f"could not read block {height}: {exc}"))
    else:
        results.append(checks.Result("Bitcoin anchor", None, "no OpenTimestamps proof downloaded"))
    return results


_MARK = {True: "OK  ", False: "FAIL", None: "--  "}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="deusproof-verify", description=__doc__.split("\n\n")[0])
    ap.add_argument("certificate_id", nargs="?")
    ap.add_argument("--base", default="https://deusproof.com", help="where to download from (default: %(default)s)")
    ap.add_argument("--bundle", help="verify a saved bundle, with no call to the registry")
    ap.add_argument("--save", help="save the downloaded record and receipts to this file")
    ap.add_argument("--file", help="the original file: its SHA-256 must be the record's output_hash")
    ap.add_argument("--issuer", action="append", default=[], help="registry did:key you trust (repeatable)")
    ap.add_argument("--explorer", default="https://blockstream.info/api",
                    help="Esplora-compatible API for the Bitcoin block header (default: %(default)s)")
    ap.add_argument("--no-bitcoin", action="store_true", help="skip reading the Bitcoin block header")
    args = ap.parse_args(argv)

    if args.bundle:
        with open(args.bundle, encoding="utf-8") as f:
            bundle = json.load(f)
    elif args.certificate_id:
        bundle = fetch_bundle(args.base, args.certificate_id)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=1)
    else:
        ap.error("give a certificate id or --bundle")

    file_sha = None
    if args.file:
        with open(args.file, "rb") as f:
            file_sha = hashlib.sha256(f.read()).hexdigest()

    results = verify_bundle(bundle, args.issuer, file_sha, None if args.no_bitcoin else args.explorer)
    _, trust_note = trusted_registry_dids(bundle, args.issuer)
    rec = bundle["record"]
    print(f"DEUSPROOF record {rec.get('id')} | agent {rec.get('agent_handle')} | output_hash {rec.get('output_hash')}")
    for r in results:
        print(f"  [{_MARK[r.ok]}] {r.name}: {r.detail}")
    print(f"\nRegistry keys trusted: {trust_note}.")
    print("What this proves: these exact bytes (by their SHA-256) existed no later than the timestamp, and the")
    print("registry recorded them in its append-only ledger. It does not prove authorship or that the content is true.")
    failed = [r for r in results if r.ok is False]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
