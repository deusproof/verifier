# Security policy

## Reporting a vulnerability

Email **contact@deusproof.com** with `SECURITY` at the start of the subject line. Please do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, and what you think an attacker could do with it. A proof of concept against your own records is welcome. We will:

- acknowledge your report within **5 business days**;
- tell you whether we can reproduce it, and our plan, within **15 business days**;
- credit you in the fix and the changelog, unless you prefer not to be named.

DEUSPROOF is run by a very small team, so these are the times we can keep. There is no paid bug bounty today.

## Scope

| In scope | Examples |
|---|---|
| This verifier (`deusproof-verify`) | A forged record that passes a check, a check that crashes on crafted input, a dependency that weakens a check |
| The registry at `deusproof.com` | Rewriting or forking the ledger, sealing under another agent's key, getting a receipt for bytes that were not sealed, bypassing rate limits, reading data that is not public |
| The agent doors | `https://deusproof.com/mcp` (MCP) and `https://deusproof.com/a2a/v1` (A2A) |

Out of scope: denial-of-service and volume testing, social engineering, physical attacks, reports from automated scanners with no demonstrated impact, and third-party services we rely on (the RFC 3161 timestamp authority, OpenTimestamps calendars, Bitcoin explorers). Problems in those are still worth telling us about if they weaken what a DEUSPROOF receipt proves.

## Testing in good faith

- Use your own records, or records you create for the test. Do not try to change, hide or claim records that belong to others.
- Keep request rates low. Every seal is permanent: test seals cannot be deleted from the append-only ledger, so please seal as few as you need.
- Identify your test traffic: put `security-research` and a way to reach you in your `User-Agent`.
- Give us a reasonable time to fix an issue before you publish it.

If you follow these rules, we will not pursue or support legal action against you for your research.

## Supported versions

| Component | Supported |
|---|---|
| `deusproof-verify` 0.1.x | Yes |
| The live registry at deusproof.com | Yes, always the deployed version |

## What a receipt is meant to prove

See [THREAT_MODEL.md](THREAT_MODEL.md): what DEUSPROOF guarantees, what it assumes, and what is planned next. A report that a receipt proves less than that document says is a security report.
