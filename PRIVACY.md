# Privacy and curation policy

This handoff was created as a fresh repository from a strict allowlist. The
original working tree was not modified or rewritten.

## Included

- Current Go source and behavior tests.
- Normative protocol and source-0.6.3 governance documentation.
- The exact proof-RPC source patch.
- Sanitized, reproducible build evidence without operator-specific paths.
- A privacy-safe, unbound trial-policy template with no live repository,
  identity, checkpoint, node, signature, CID, or transaction identifiers.
- A compact status checkpoint and verification script.

## Excluded

- All credentials, secret values, key files, passphrases, and account data.
- Local usernames and absolute paths.
- Hostnames, SSH aliases, remote account names, ports, private service names,
  datadir paths, and API-key locations.
- Node PIDs, raw RPC bodies, raw logs, screenshots, browser state, temporary
  scripts, and command transcripts.
- Live balances and stake observations tied to a specific identity.
- Binaries, source archives, chunk stores, build caches, generated previews,
  and test-run output.
- Historical and rejected artifacts, superseded policies, invitation drafts,
  signing plans, pinning scripts, deployment plans, and receipts.
- Published actions, repository identifiers, identity addresses, DIDs, public
  keys, signatures, CIDs, transaction metadata, and exact proposal object IDs
  tied to the live trial.
- Git bundles, mail patches, and exact diffs carrying embedded author metadata
  or live repository history.
- The source repository's prior filesystem history.

## Generic security interfaces

The implementation necessarily names generic interfaces for local signing and
RPC authentication. Names appearing in source or documentation are interface
descriptions only; this repository contains no real secret value, user-specific
secret path, or credential file.

Tests may contain deterministic synthetic hashes, addresses, signatures, and
key-like fixtures. End-to-end mirror tests generate fresh synthetic keys,
signed actions, and Git bundles only inside temporary test directories. Public
cryptographic identifiers are still excluded when they link this handoff to a
live identity, repository, transaction, or publication history.

The privacy scanner permits only the exact, documented synthetic identifiers
used by tests and the public protocol contract constant required by the UI.
It rejects any other fixed address, DID, Radicle repository ID, public key,
armored SSH signature, CID-shaped value, or long `0x` action/signature value.

## Before sharing

Run:

```sh
./scripts/verify-handoff.sh
```

Then inspect the single root commit. Before publication, `git remote -v` must
be empty. After publication, the only permitted remote is the official
`ubiubi18/idena-git-forge` origin. If additional evidence is added later,
repeat both the working-tree scan and a scan of every reachable Git object
before sharing.

For ongoing development, run `./scripts/install-git-hooks.sh` once per clone.
The repository also contains a GitHub workflow that applies the same privacy
policy, runs Gitleaks, and tests the source on every push and pull request.
