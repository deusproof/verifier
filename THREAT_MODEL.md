# Threat model

What a DEUSPROOF receipt proves, who you have to trust for it, and what we are doing to need less trust.

## What a receipt proves

A record says: **these exact bytes, identified by their SHA-256, existed no later than time T, and the registry recorded them in its append-only ledger.**

It does not prove:

- who wrote the bytes, or that they are true;
- that nobody had them earlier;
- that a sealed log was complete, only that it has not changed since it was sealed.

An agent's birth certificate proves when the registry inscribed the agent. It is not a legal identity, and it is not the date the agent was created.

## The pieces and who checks them

| Piece | What it is | Who you trust for it |
|---|---|---|
| Fingerprint | SHA-256 of the content; the content never reaches us | Nobody: you recompute it |
| RFC 3161 timestamp | A token from an independent timestamp authority over `prompt_hash:output_hash:certificate_id` | The authority's clock and key (today FreeTSA) |
| Bitcoin anchor | An OpenTimestamps proof committing the same bytes to a Bitcoin block | Bitcoin's proof of work, plus one block-header read (your own node removes even that) |
| Ledger entry | A hash-chained entry naming the record's id, agent, platform and fingerprint | The registry, until witnesses co-sign (see below) |
| Merkle inclusion and checkpoint | An audit path to a Merkle root, and the root and tree size signed with the registry's Ed25519 `did:key` | The registry's signing key, published at `/api/anchors/issuer` with its history |
| Agent signature | For signed records, the agent's own Ed25519 signature over its seal | The agent's key, which we never hold |

`deusproof-verify` recomputes every row on your machine. With `--bundle` it makes no call to us.

## Who might attack, and what stops them

| # | Attack | What stops it today | Planned next |
|---|---|---|---|
| T1 | **The registry backdates a record** | The timestamp authority and Bitcoin fix the latest possible time independently of us. We cannot make a seal look older than its receipts. | A second timestamp authority |
| T2 | **The registry edits or deletes a record after the fact** | Each entry is hash-chained to the previous one and covered by signed checkpoints; receipts already handed out stop verifying | Witnessed checkpoints (T3) |
| T3 | **The registry shows different histories to different people (a fork)** | Signed checkpoints let two readers compare what they were shown; Bitcoin anchors bound each record's time | Consistency proofs between checkpoints (RFC 6962 style) and checkpoints co-signed by independent witnesses, so a fork needs the witnesses to collude |
| T4 | **Someone seals under another agent's name** | Anyone can seal under any name. Only a record carrying the agent's own signature binds it to the agent; others are marked as not signed by its key | Agents that took their certificate seal with their key by default |
| T5 | **The registry's signing key is stolen** | Timestamps and Bitcoin anchors do not depend on that key, so past times stay provable; key changes are published in the key history; pin a key with `--issuer` | Witness co-signatures, so one key alone cannot sign a new history |
| T6 | **Agents the registry indexed itself** | Their identifiers were derived by the registry, so we hold the private half until the agent takes possession by signing a challenge with its own key. The certificate says so | Keep derivation keys apart from the registry's signing key |
| T7 | **An agent rewrites its own log before sealing** | Nothing can: a seal fixes what existed when sealed | The runtime, not the agent, seals the log head at the end of each session ("agent log receipts") |
| T8 | **Guessing sealed content from its fingerprint** | Content is never sent, but a short or predictable text can be guessed by hashing candidates | Guidance to add a random salt before hashing anything short or sensitive |
| T9 | **The timestamp authority lies or is compromised** | The Bitcoin anchor gives a second, independent bound on time | A second authority |
| T10 | **Flooding the registry** | Rate limits per IP and per agent | — |

## What you can do to trust us less

1. Keep the bundle (`deusproof-verify <id> --save bundle.json`) with your copy of the content.
2. Pin the registry key you obtained elsewhere with `--issuer`.
3. Read the Bitcoin header from your own node (`--explorer`).
4. Check the RFC 3161 token against the authority's published certificate, or with `openssl ts -verify`.
5. For logs: hash-chain them yourself and seal only the head, so nothing but a fingerprint leaves your machine.

## How it is built

DEUSPROOF is written with an AI coding assistant under the direction of its founder, who reviews and answers for every release. An independent security audit is planned and will be published in full. To report a problem, see [SECURITY.md](SECURITY.md).
