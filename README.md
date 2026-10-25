# deusproof-verify

Check a [DEUSPROOF](https://deusproof.com) record yourself, without trusting DEUSPROOF.

DEUSPROOF is a free, open registry for AI agents: each agent can hold a public birth certificate, and agents seal the SHA-256 fingerprints of what they produce, such as files, logs or mandates. This tool takes one record and re-does, on your machine, every check the registry claims to have done.

```bash
pip install git+https://github.com/deusproof/verifier   # or, from a clone: pip install .
deusproof-verify 3c54818a-8ffc-4afb-b4c6-548a217fe32b
```

```
DEUSPROOF record 3c54818a-... | agent anonymous | output_hash 1d07cddf...
  [OK  ] sealed seed: seed is prompt_hash:output_hash:id
  [OK  ] manifest signature: signed by did:key:z6MkjQKb...
  [OK  ] ledger entry: the entry hash commits to this record's id, agent and fingerprint
  [OK  ] Merkle inclusion: entry is in the tree with root 4bfa3072...
  [OK  ] signed checkpoint: root and size ... signed by did:key:z6MkjQKb...
  [OK  ] RFC 3161 timestamp: 2026-10-16T01:59:45+00:00 by www.freetsa.org (signature valid ...)
  [OK  ] Bitcoin anchor: committed in Bitcoin block 971659 (header read from https://blockstream.info/api)
```

## What it checks

| Check | What it recomputes |
|---|---|
| **Sealed seed** | The bytes both timestamps cover are `prompt_hash:output_hash:certificate_id` of this record. With `--file`, your file's SHA-256 is the record's `output_hash`. |
| **Manifest signature** | The record's manifest hashes to `manifest_hash`, and the Ed25519 signature verifies under the registry's `did:key`. |
| **Ledger entry** | `sha256(canonical JSON)` of the published entry reproduces `ledger_entry_hash`, and the entry names this record's id, agent, platform and fingerprint. |
| **Merkle inclusion** | The audit path from that entry leads to the checkpoint's Merkle root (RFC 6962 leaf/node prefixes). |
| **Signed checkpoint** | `root:tree_size` is signed by a registry key. |
| **RFC 3161 timestamp** | The token's message imprint is the seed's digest, and the timestamp authority's CMS signature verifies with the certificate it embedded. |
| **Bitcoin anchor** | The OpenTimestamps proof commits the seed to a Bitcoin block's Merkle root, read from a public block explorer of your choice. |

`OK` passed, `FAIL` did not, and `--` means it could not be checked (for example, the Bitcoin attestation is still pending). The tool exits with 1 if anything fails.

## Without the registry at all

```bash
deusproof-verify <id> --save bundle.json     # keep the record and every receipt in one file
deusproof-verify --bundle bundle.json        # re-check it later: no call to DEUSPROOF
```

The only outside call left is one Bitcoin block header. Choose any Esplora-compatible explorer with `--explorer`, for example `https://mempool.space/api` or your own node's API, or skip it with `--no-bitcoin`.

## What you still trust, and how to stop

- **The registry's key.** By default the tool trusts the keys the registry publishes at `/api/anchors/issuer`. Pin one you obtained elsewhere with `--issuer did:key:...`.
- **The timestamp authority's certificate.** The tool checks the signature with the certificate inside the token. To anchor that certificate, compare it with the authority's published one (for FreeTSA, `freetsa.org/files/`), or run `openssl ts -verify` on the saved receipts.
- **The block explorer.** One header read. Use your own node to remove it.

## What a record proves, and what it doesn't

It proves that these exact bytes, identified by their SHA-256, existed no later than the timestamp, and that the registry recorded them in its append-only ledger. It does not prove who wrote them, that they are true, or that nobody had them earlier.

## Security

What a receipt guarantees, what it assumes and what is planned next: [THREAT_MODEL.md](THREAT_MODEL.md). To report a problem: [SECURITY.md](SECURITY.md).

## How this was built

DEUSPROOF, including this tool, is written with an AI coding assistant (Claude) under the direction of its founder, who reviews and is accountable for every release. The tests in `tests/` use real receipts from a production record and synthetic forgeries.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2026 REDGROUND BLOCKCHAIN LLC, the Delaware company that operates DEUSPROOF.
