# Idena-Governed Radicle Forge

This is a sanitized source handoff for the Idena-governed Radicle forge.
It contains the current source, behavior tests, normative protocol, governance
policy template, proof-RPC source patch, and a compact current-status
checkpoint. Published trial actions, repository bundles, exact proposal diffs,
live identity identifiers, and their historical Git objects are intentionally
excluded. Tests create synthetic signed actions and bundles at runtime.

Start with [STATUS.md](STATUS.md). The protocol is defined by [SPEC.md](SPEC.md)
and [docs/GOVERNANCE_TRUST_MODEL_0.6.3.md](docs/GOVERNANCE_TRUST_MODEL_0.6.3.md).

## Verify

Requirements:

- Go 1.26 or newer;
- Git; and
- optional Docker/Podman for independently rebuilding the Linux/AMD64 node
  extension described in [node-extension/README.md](node-extension/README.md).

Run:

```sh
./scripts/verify-handoff.sh
```

The verifier checks the curated evidence hashes, rejects common private-data
and generated-artifact paths, and runs the Go test suite. It does not contact a
node, deploy anything, sign, pin, publish, or broadcast.

## Secret-leak prevention

Enable the repository's versioned pre-commit and pre-push checks after cloning:

```sh
./scripts/install-git-hooks.sh
```

The pre-commit hook scans staged paths and content. The pre-push hook scans all
reachable commits. Both reject credential-shaped values, private filesystem or
network locations, personal email metadata, unreviewed bundles, compiled
binaries, and files excluded by the curation policy. If Gitleaks is installed,
the hooks run it too. The repository's Gitleaks allowlist is limited to one
documented synthetic test DID. GitHub CI repeats the privacy scan, runs
Gitleaks, and executes the Go test suite. GitHub's native secret scanning and
push protection should be enabled when the repository plan supports them.

## Handoff boundary

This repository intentionally does not contain:

- credentials, private keys, API keys, passphrases, or private configuration;
- operator hostnames, host aliases, account names, local absolute paths,
  service paths, datadir paths, or credential-file locations;
- production binaries, release archives, chunks, screenshots, browser state,
  raw logs, or generated test history;
- published trial actions, repository or review bundles, exact trial proposal
  diffs, live identity identifiers, signatures, CIDs, or transaction metadata;
- historical/rejected deployment plans and execution receipts;
- live stake observations, private operational metadata, or signer material;
  or
- any Git history predating this sanitized handoff.

See [PRIVACY.md](PRIVACY.md) for the complete curation and verification rules.
