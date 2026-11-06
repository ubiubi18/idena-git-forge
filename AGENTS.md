# Working instructions

Read `STATUS.md`, `PRIVACY.md`, `SPEC.md`, and
`docs/GOVERNANCE_TRUST_MODEL_0.6.3.md` before changing behavior.

- Treat this repository as source and review evidence, not deployment approval.
- Preserve the source-0.6.3 governance rule and fail closed on missing or mixed
  policy identifiers, proofs, exact revisions, or required content.
- Do not substitute live balances or indexer assertions for canonical
  checkpoint proofs.
- Do not infer governance authority from node count, operator count, builder
  role, repository initialization, or infrastructure access.
- Never add credentials, secret values, local absolute paths, hostnames,
  account names, service paths, datadir paths, raw operational logs, or signer
  material.
- Treat live public addresses, DIDs, public keys, repository IDs, signatures,
  CIDs, transaction metadata, and Git object history as privacy-sensitive when
  they link the handoff to a real identity, repository, or publication.
- Keep generated binaries, archives, screenshots, browser state, deployment
  receipts, and test-run output outside this repository.
- Use runtime-generated synthetic fixtures in tests. Do not copy production,
  published-trial, or operator data into the tree or its Git history.
- Enable `.githooks` with `./scripts/install-git-hooks.sh` after cloning.
- Run `./scripts/secret-scan.sh --staged` before committing and
  `./scripts/verify-handoff.sh` before sharing a handoff snapshot.
- Deployment, signing, pinning, publication, transactions, and external
  messages require separate explicit approval and environment-specific plans.
