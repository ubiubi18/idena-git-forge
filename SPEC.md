# Idena-Governed Radicle Forge

## Boundary

Radicle Heartwood is the forge. Git repositories, repository IDs, nodes,
issues, patches, revisions, comments, reviews, and labels use Radicle's COB
model and CLI semantics.

Idena is the chain clock, identity authority, content replication layer, and
stake-governance layer. Runtime operation does not depend on a Radicle seed,
`seed.radicle.dev`, a Radicle web service, GitHub, or another hosted forge.
Signed forge actions are tagged inline Idena self-send payloads. Large Radicle
storage bundles and diffs move through Idena IPFS.

Any replica can reproduce a publication from its canonical Idena block
and its own Idena IPFS view. Permanent mirroring is admitted only after the
inline action, signatures, Radicle binding, every raw CID and the exact
quarantined Radicle bundle have passed locally. A mirror receipt records those
checks but cannot prove operator independence or continued future pinning;
those remain externally observable availability properties. Operator
independence is not a governance prerequisite. Multiple nodes under one
disclosed operator provide replica redundancy but remain one operational
failure domain.

After a successful mirror pin, an operator may attach a domain-separated
Idena `dna_sign` signature to the canonical receipt. The recovered address
binds one Idena key to that exact claim without a transaction. It does not
replace the checkpoint eligibility proof, establish distinct human control,
or prove that the content remains online.

The repository is the public Radicle storage repository. A checkpoint record
places `refs/idena/epoch/<epoch>/canonical` at the governance-selected commit.
That ref is the forge's canonical authority. Runtime code does not read
Radicle delegates or `refs/heads/main` when deciding what a repository contains.
See "Canonical authority" below.

## Acceptance criteria

1. An anchor is recognized for identity and quota accounting only when:
   - an Idena self-send carries the tagged canonical action bytes containing
     its exact repository RID, COB type, COB ID, operation OID and Git head;
   - the anchor is signed by the transaction sender;
   - the sender has a valid `Newbie`, `Verified`, or `Human` identity in the
     post-transition state of the checkpoint;
   - that DID signs a binding message containing the Radicle RID, Idena
     address, public key, and epoch; and
   - the canonical payload and actor fields are structurally valid.

   A recognized anchor is admitted as a valid Radicle operation only when:
   - the Radicle operation is signed by the same DID named in the anchor;
   - the referenced Radicle operation is present in a pinned storage bundle;
   - the content object ID of the bundle's signed repository identity document
     encodes to the declared Radicle RID; and
   - for repository creation, the format-v3 identity document's immutable
     `initializer` DID equals the action actor, owns the signed namespace, and
     signs the separate Radicle/Idena binding.

   Radicle and Git cannot stop a person from creating local objects. This
   protocol controls which published operations it recognizes.

2. Commits, issues, patch revisions, comments, and reviews are created with
   Radicle throughout the epoch. Each one is published as a tagged inline
   self-send action; its larger referenced bundle and diff remain in Idena IPFS.
   A review applies to one exact Radicle revision ID. A new Radicle revision
   requires new reviews. A review edit is traced through its original Radicle
   review operation before it can count for a revision.

3. Settlement happens at a canonical block carrying `ValidationFinished`.
   The committed post-transition identity state is the only stake snapshot.
   Live balances, later balances, and cumulative deposits are not used.
   Native stake changes included through that block are reflected once in the
   snapshot; no earlier deposit history adds weight.
   There is no additional one-hour delay.

   The read-only `dna_epochCheckpoint` extension authenticates the exact
   canonical `ValidationFinished` header, its committed state root, and its
   post-transition epoch. Its response includes a portable IAVL membership
   proof for the global state value at key `0x03`; clients archive this proof
   so the epoch binding remains verifiable after pruning.
   `dna_epochIdentityProof` returns an identity membership proof against that
   same root. Ordinary nodes hold approximately the latest 100 state versions,
   so clients request and pin both proofs promptly. Clients may use the Idena
   indexer `DataWithProof` endpoint as a
   fallback identity-proof source. That endpoint returns the same IAVL proof
   family, which clients verify against the locally observed checkpoint state
   root. A malicious or stale indexer response cannot create a valid
   checkpoint.

4. A ballot executes only when its unique eligible voters:
   - number at least three;
   - include at least two distinct approvals;
   - have a combined raw native stake of at least 500,000 iDNA, counting both
     approval and rejection voters; and
   - assign more combined stake weight to approvals than to rejections. A tie
     does not approve.

   There is no individual 500,000 iDNA minimum. Exactly three voters still
   require two approvals because of the explicit approval floor. With more
   than three voters, approval identities do not need to be a numerical
   majority: once the two-approval floor is satisfied, the strict weighted
   majority decides between approval and rejection. A rejection does not
   itself veto a ballot that satisfies the participation, approval, raw-stake,
   and weighted-majority gates.

   Each voter contributes:

   ```text
   floor(raw_stake^(9/10))
   ```

   using integer arithmetic. This preserves Idena's staking reward exponent.
   The 500,000 iDNA admission gate uses raw stake; the approval-majority gate
   compares the summed `stake^0.9` weight on each side of the ballot.

   Because weight is calculated per eligible identity and then summed,
   splitting a fixed total stake `S` evenly across `n` valid identities yields
   approximately `n^0.1 * S^0.9` total weight before integer flooring. The
   identity-count effect is therefore positive but sublinear. It creates no
   weight without stake and does not change the 500,000-iDNA raw-stake gate.

   Identity count is a participation and deliberation floor, not Sybil
   resistance or a standalone one-person-one-vote term. Its only influence
   beyond those floors is the sublinear stake-partition effect above. Any identity
   proven `Newbie`, `Verified`, or `Human` at the checkpoint may join the
   ballot; the patch builder has no special role and need not vote. One voter
   may supply most or all of the 500,000-iDNA raw threshold as long as the
   three-voter, two-approval, raw-stake, and weighted-majority gates also pass.
   The result retains an `identityMajority` field for compatibility and
   transparency, but source version 0.6.3 does not use it as a decision gate.

   Node count and operator count have zero governance weight. Clients may
   cross-check any number of RPC replicas, including several controlled by one
   disclosed operator. Every configured view must agree before archival, but
   the checkpoint proofs and stake ballots—not the replica count—authorize the
   result.

5. One Idena identity has at most 20 recognized anchors per epoch. Canonical
   envelope and payload shape, transaction sender/self-send/epoch, Idena
   signature, DID/Idena binding, and checkpoint identity proof determine which
   anchors consume quota. Duplicate handling and canonical order are applied
   before the quota. Referenced Radicle content is verified only after these
   content-independent slots are assigned. Invalid available content is
   rejected from governance and still consumes its slot. Unavailable required
   content also consumes its slot, but stops settlement instead of becoming a
   replica-local rejection. This prevents nodes with different local caches
   from assigning either the twentieth slot or the canonical winner
   differently.
   Reviews, review changes, and merge-request labels count. Native staking and
   delegation transactions do not.

6. For each Radicle repository and checkpoint, at most one public patch can
   become canonical. A patch revision is eligible only when:
   - it is an open Radicle patch revision;
   - an eligible identity added Radicle label `idena/merge-request` to it;
   - the revision satisfies the two-approval, three-voter, raw-stake, and
     weighted-majority gates;
   - its Radicle base equals the canonical governance head; and
   - its Radicle head is a Git fast-forward.

   Candidates are ordered by:

   1. higher approval-minus-rejection integer weight;
   2. higher approval integer weight;
   3. higher combined voter stake;
   4. earlier canonical Radicle merge-label anchor;
   5. lexicographically smaller Radicle revision ID;
   6. lexicographically smaller Radicle patch ID.

   Approval count is not a ranking key after the minimum and strict-majority
   gates pass. The canonical result records both the patch ID and exact winning
   revision ID.

   No maintainer, bot, web service, or operator chooses the result.

7. Each publisher pins its Radicle storage bundle, exact Radicle operation and
   patch diff in its Idena IPFS node. CID references are CIDv1 raw blocks using
   SHA2-256. Scanners keep recognized objects on a lease through the
   publication epoch and following epoch; they do not promote data before full
   Radicle validation. After authenticated reduction, participating clients
   permanently retain every accepted action and referenced object for its
   active repository. Replica clients restore bundles from Idena IPFS into
   local Radicle storage. Restore imports only the action-bound actor namespace
   and rejects signed-ref rollback or divergence.

   Idena can prove a CID was referenced and can make bytes retrievable through
   replication. It cannot prove another machine retained the bytes. Missing
   required content leaves the checkpoint unsettled on every compliant client;
   a client must not reject the unavailable action and choose an alternative
   merge. Local availability is displayed by the UI but is excluded from the
   canonical checkpoint JSON and input digest.

   A repository deletion must pass the same quorum as a patch. Its verified
   checkpoint records `pruneAfterEpoch = deletionEpoch + 2`, providing one
   complete grace epoch. `forge prune --delete` refuses to remove content before
   that epoch or when the object is still referenced by another active
   repository.

8. The preview shows the Radicle patch revision, diff, Radicle DID, Idena
   author, review verdicts, checkpoint winner, and object availability.

## Canonical action transport

An ordinary zero-value self-send carries:

```text
IDENA_GIT_ACTION_V1\0 || uint32_be(action_length) || canonical_action_json
```

The length is bounded to 64 KiB and must consume the remainder of the payload
exactly. An ordinary send without the tag is ignored. A malformed tagged send
is recorded in canonical transaction order and deterministically rejected.
`StoreToIpfsTx` transactions are never action-discovery candidates, so their
availability cannot gate checkpoint settlement.

The canonical action JSON is:

```json
{
  "schema": "idena-radicle/anchor/v1",
  "kind": "radicle_review",
  "repository": "rad:z...",
  "epoch": 42,
  "author": "0x...",
  "radicleIdentity": "did:key:z...",
  "radiclePublicKey": "ssh-ed25519 ...",
  "bindingSignature": "<armored SSH signature>",
  "nonce": "16-byte-random-hex",
  "payload": {},
  "signature": "0x..."
}
```

The Radicle binding is an SSH signature by the Radicle Ed25519 key over:

```text
idena-radicle-bind/v1
rid=<repository id>
idena=<address>
did=<did:key>
key=<canonical public key>
epoch=<epoch>
```

The outer Idena signature uses Idena's `prefix` signing format. The node RPC
`dna_sign` produces that signature.

## Radicle subjects

The anchor payload names existing Radicle objects:

- repository identity: RID, head OID and storage bundle;
- commit publication: Radicle ref and commit OID;
- issue: issue COB ID and operation OID;
- patch revision: patch ID, revision ID, base OID, head OID and bundle;
- comment: target COB ID and comment operation OID;
- review: patch ID, revision ID and review operation OID;
- merge request: patch ID, revision ID and label operation OID.

The bridge reads the operation graph from the real `rad cob log --format json`
and state from `rad cob show --format json`. It does not implement a competing
issue or patch format.

## Canonical order

Anchors are ordered by checkpoint block height, transaction index, then anchor
hash. One duplicate anchor hash is kept at its earliest position. This order
controls quota, review replacement, and merge-label tie-breaking.

The checkpoint binds its result to the block hash and state root. If that block
leaves the canonical chain, the checkpoint result is stale and must be
recomputed.

Raw checkpoint JSON is not accepted by the production reducer. Mainnet replay
starts at activation epoch 235, when the first forge action was published, and
must include every consecutive epoch from that point, including empty epochs.
Every checkpoint input and result also carries the exact reducer-policy
identifier accepted by that source version. The identifier contains a SHA-256
digest of the canonical rule definition and is part of the checkpoint input
digest. Missing, legacy, unknown, or mixed policy identifiers fail before
canonical-chain authentication or Radicle verification.
The accumulator starts empty. Prior repository heads and deletion records are
derived only from earlier authenticated results; serialized
`previousHeads`/`previousDeletions` fields are not protocol input. Before
reduction, the local Idena client must authenticate the supplied height, block
hash, state root, timestamp, and `ValidationFinished` flag against
`bcn_blockAt`; verify the archived global-state epoch proof against that root
(or use the latest-checkpoint-only compatibility path for legacy inputs); walk
the canonical parent chain back to the preceding checkpoint; and reconstruct
every tagged inline forge action from the transactions in that interval. A
fresh scanner obtains the portable epoch proof through `dna_epochCheckpoint`
while the state version is retained. The listed actions must match the chain
reconstruction exactly in count, order, transaction metadata, and bytes.
Successful verification creates a sealed in-memory reducer capability. The
seal rejects mutation between authentication and reduction. The separate
fixture reducer is non-consensus test/UI tooling and its output is not protocol
evidence.

## Global epoch record

The checkpoint epoch proof covers the full protobuf-encoded global state value
at state-tree key `0x03`. Field 1 is the committed post-transition epoch. The
entire value, leaf, and IAVL path are retained; clients do not trust an
unproven epoch integer from an archived RPC response.

Checkpoint replay internally carries verified heads and confirmed repository
deletions. A caller cannot seed or replace that state, and a deleted repository
cannot be resurrected by a later PR.

## Native identity record

The proof covers the state-tree value at key `0x02 || address`.

- field 1: big-endian raw stake;
- field 4: identity state;
- eligible states: `3 Verified`, `7 Newbie`, `8 Human`.

The identity proof may come from either the local node or the Idena indexer
proof endpoint, but both paths are verified against the same checkpoint state
root.

## Canonical authority

Radicle repository identity documents contain an immutable initializer DID and
protocol-level metadata for ordinary branch writes. The initializer binds the
RID to the actor that created and signs the repository namespace, but grants no
merge authority. Heartwood identity format version 3 has no delegate or
threshold fields and rejects pre-initializer and delegate-bearing documents.
Canonical merge rules accept only `"allow": "idena"` with two approvals, and
repository identity metadata is immutable.

The only canonical branch recognized by the forge is:

```text
refs/idena/epoch/<epoch>/canonical
```

The ref points to the deterministic quorum winner's Git commit. The reducer
never reads `refs/heads/*`, delegate lists, thresholds, or signatures as
governance authority. Any client can reproduce the same canonical ref from
Idena chain data. Stock Radicle tooling may still need an adapter to display
this ref as its default branch, but that presentation layer has no governing
power.

## UI distribution

The checkpoint UI has a separate static distribution path. `forge export-ui`
embeds the checkpoint and locally available diffs in one HTML file with no
network requests. `forge share-ui` adds those exact bytes to the local Idena
node's IPFS with a permanent pin and emits an `idena.social` `makePost` plan.
It cannot broadcast the plan; posting is a separately reviewed operation in an
Idena client.

The social message uses the discovery token:

```text
idena-radicle://<CID>
```

A compatible Idena social client fetches the HTML with `ipfs_get` from its own
node, prepends a restrictive non-networked CSP, and renders it in an iframe
sandbox with no permissions. The UI is static for this reason. No GitHub,
gateway, seed, HTTP origin, or centralized website is required to derive or
view a published checkpoint.
