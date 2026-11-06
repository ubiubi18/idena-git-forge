# Current status

Prepared: 2026-11-06

## Executive state

The forge source is at version 0.6.3 and implements the current governance
rule. It is source code, not an approved release. The first trial is not
settled, no governed pull request has been published, and no future checkpoint
has been selected.

The missed epoch-235 checkpoint remains failed closed. It was not captured
through the authenticated two-observer proof path, so it must not be treated as
archived or reconstructed from later live balances. A future trial must
re-anchor at a new checkpoint after proof-RPC capability is restored.

## What is implemented

- Source-0.6.3 policy binding and deterministic reduction.
- Permissionless voter admission for checkpoint-proven `Newbie`, `Verified`,
  and `Human` identities.
- At least three distinct eligible voters and at least two approvals.
- At least 500,000 iDNA of combined raw checkpoint stake across approval and
  rejection voters.
- Strict approval majority by deterministic `floor(rawStake^(9/10))` weight.
- No numerical identity-majority gate and no governance weight for nodes,
  operators, builders, or repository initializers.
- Exact-revision vote binding and deterministic candidate ordering.
- Portable IAVL checkpoint and identity/stake proof verification.
- Local Radicle storage, binding, content, mirror, and UI support with the
  security boundaries documented in this repository.

The exact reducer policy identifier is:

```text
idena-radicle/reducer-policy/v3:sha256:4dd6a297acaa7e82ce83bf5b335dfd03196e51a29894127db893fedbc203a4db
```

## Proof-RPC candidate

The read-only checkpoint and identity-proof extension was ported to the
current security-candidate source base and built twice from separate clean
exports. The two Linux/AMD64 outputs were byte-identical.

- source repository: `https://github.com/ubiubi18/idena-go.git`;
- source checkout: `3359e6a1ed7bc3ac0c3ebe231ed54fa827fd263e`;
- patch: `node-extension/idena-go-checkpoint-proof-security-candidate.patch`;
- patch SHA-256:
  `aebf20840bdf5a705794c2dac25eaf01e37a50a8e5fa66754e4becba4ac13bb0`;
- expected Linux/AMD64 artifact bytes: `99,341,392`;
- expected artifact SHA-256:
  `5e818d00cb916c00276e3a0d27f0a8c909c00afad78bf65a1253a37c0f09a75e`;
- reported version: `idena-go version 1.1.2`.

The binary is deliberately not committed here. Rebuild it from the exact
source and patch, then compare its bytes and digest with
[node-extension/build-evidence.json](node-extension/build-evidence.json).

This is same-operator reproducibility evidence, not independent second-party
reproduction. The compatibility lock remains a candidate and has not been
advanced for the proof patch.

## Last operational observation

The last read-only two-observer preflight in this workstream was performed on
2026-11-05. At that time:

- both observer services were active with zero automatic restarts;
- both installed and running executables still had SHA-256
  `9c31a59f767d841e6e1f15416a8716316ad9601cce29306d7e56bba403eb917c`;
- the preserved original rollback executables still had SHA-256
  `17741e1cff7b5ff78339b9fcb574146fb03da15a8e6e7b3a1a743e78dbb943e9`;
- the proof-RPC methods were still unavailable;
- the two observers agreed on epoch 236 and a common canonical head;
- the candidate had not been staged;
- no new rollback copy had been created; and
- no service had been restarted or binary replaced by this workstream.

Those facts are a dated observation, not a promise about current external
state. Any operator must repeat the complete read-only preflight before a
deployment decision.

Environment-specific deployment details are intentionally excluded from this
handoff. They contained private infrastructure pointers and cannot safely be
reused by another operator.

## Privacy-safe handoff boundary

The earlier trial's signed action, exact proposal diff, repository and review
bundles, live addresses, DIDs, public keys, repository IDs, signatures, CIDs,
transaction metadata, and embedded Git author history are not included. Those
values were public protocol evidence, but they also link a repository reader
to the live project identities and are unnecessary for a source handoff.

The regression suite retains the same bundle, binding, content-verification,
pin-before-attest, and tamper-rejection behavior with synthetic artifacts
created in temporary test directories. The policy JSON is an unbound template,
not a record of a live repository or checkpoint.

No publication, signing, pinning, transaction, social post, or external
message is authorized by this repository.

## Required next work

1. Independently review the source, governance model, and proof patch.
2. Run `./scripts/verify-handoff.sh` from a clean checkout.
3. Independently rebuild the node-extension candidate and require the exact
   recorded artifact digest.
4. Create a new environment-specific, exact-hash deployment plan without
   importing any prior operator's hostnames, credentials, or filesystem paths.
5. Deploy one observer at a time only after explicit approval, preserving a
   verified rollback and requiring synchronization and canonical-chain
   agreement before touching the next observer.
6. After two proof views are healthy, define a future activation epoch and a
   new versioned capture helper. Do not reuse the immutable epoch-235 helper.
7. At that future checkpoint, collect canonical identity and raw-stake proofs
   for every voter and enforce the complete 0.6.3 rule.

## Evidence classification

This repository is a compact continuation checkpoint. It intentionally
summarizes the technical state without embedding raw operator logs, receipts,
binaries, snapshots, live identity artifacts, exact trial history, or
superseded plans. Obtain any omitted evidence through a separately reviewed,
privacy-safe transfer if it is needed for an audit.
