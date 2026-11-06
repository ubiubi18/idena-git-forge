# Proof-RPC node extension

This directory contains the source patch and sanitized build evidence for the
read-only `dna_epochCheckpoint` and `dna_epochIdentityProof` RPC extension.

The handoff does not include a node binary. Rebuild from:

- repository: `https://github.com/ubiubi18/idena-go.git`;
- checkout: `3359e6a1ed7bc3ac0c3ebe231ed54fa827fd263e`;
- patch: `idena-go-checkpoint-proof-security-candidate.patch`;
- patch SHA-256:
  `aebf20840bdf5a705794c2dac25eaf01e37a50a8e5fa66754e4becba4ac13bb0`.

Use the exact pinned toolchains, commands, and expected output digest in
[build-evidence.json](build-evidence.json). Build twice from separate clean
exports and require byte identity.

Only invoke a candidate binary as `<binary> --version` for a version probe.
The positional argument `version` starts a normal node and must not be used.

This evidence does not approve release, deployment, service restart, datadir
access, signing, pinning, publication, or transaction broadcast.
