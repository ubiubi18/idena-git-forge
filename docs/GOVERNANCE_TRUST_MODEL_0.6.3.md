# Governance and replica trust model for source 0.6.3

This document is normative for source version 0.6.3. It supersedes the
source-0.6.2 decision rule for future settlement without rewriting the pinned
0.6.2 trust model, policy, manifests, plans, receipts, CIDs, or binaries.

## Merge authority

Only authenticated Idena actions and the canonical epoch checkpoint decide a
merge. A node, operator, publisher, repository initializer, Radicle delegate,
maintainer, bot, web service, or builder has no special merge weight.

A pull-request revision can pass only when all of these conditions hold at the
`ValidationFinished` checkpoint ending its publication epoch:

- at least three distinct eligible Idena identities cast ballots for that
  exact revision;
- at least two distinct eligible identities approve;
- approval and rejection voters together have at least 500,000 iDNA of raw
  native checkpoint stake;
- approvals have a strict majority of the deterministic
  `floor(rawStake^(9/10))` weight; and
- the exact revision has a merge-request anchor, uses the canonical base, and
  is a Git fast-forward.

A weighted tie does not approve. Approval identities do not need to be a
numerical majority of all participating identities. The canonical result keeps
`identityMajority` as an informational compatibility field, but it is not a
source-0.6.3 decision gate.

## Identity and stake power

Every identity proven as `Newbie`, `Verified`, or `Human` at the checkpoint
may vote on the exact revision. Other identity states are ineligible. The
builder has no privileged role and need not vote.

Identity count supplies two explicit participation requirements: one slot
toward the three-voter floor and, for an approval ballot, one slot toward the
two-approval floor. There is no separate one-person-one-vote term and identity
count supplies no direct candidate-ranking weight.

Each eligible ballot contributes checkpoint stake weight:

```text
floor(raw_stake^(9/10))
```

calculated with deterministic integer arithmetic. This makes voting power
sublinear in stake. The 500,000-iDNA gate uses raw stake across both sides;
there is no per-address minimum.

Because each eligible identity's weight is calculated separately and the
weights are then summed, splitting a fixed total stake `S` evenly across `n`
valid identities produces approximately `n^0.1 * S^0.9` power before integer
flooring. The identity-count effect is therefore positive but sublinear. This
is not Sybil resistance: additional valid identities can give the same stake a
limited partitioning advantage. They cannot create power without checkpoint
stake or replace the 500,000-iDNA raw-stake threshold.

Consequently, one 1,000,000-iDNA approval against three 10,000-iDNA rejections
still fails because there is only one approval. If a second eligible identity
approves and all other gates pass, the ballot is decided by the summed
sublinear stake weight even when rejection identities are the numerical
majority.

Each identity's latest recognized ballot for one exact revision is counted. A
changed revision requires new ballots.

## Candidate ordering

When several revisions pass for one repository in the same checkpoint,
candidates are ordered by:

1. higher approval-minus-rejection integer weight;
2. higher approval integer weight;
3. higher combined participating raw stake;
4. earlier canonical merge-request order; and
5. lexicographically smaller exact revision ID; and
6. lexicographically smaller Radicle patch ID.

Identity count does not break ties or rank candidates.

## Reducer-policy binding

Every source-0.6.3 checkpoint input and result carries the exact current
`idena-radicle/reducer-policy/v3:sha256:...` identifier. The digest covers the
canonical rule definition, including identity eligibility, participation
floors, raw-stake threshold, sublinear weighting, strict weighted majority,
deletion delay, and total candidate order. The policy identifier is also part
of the input digest. Missing, legacy, unknown, or mixed policy identifiers fail
before chain authentication, Radicle inspection, result display, or repository
materialization.

Read-only Radicle verification uses a public-only profile containing
`config.json` and `keys/radicle.pub`. It neither reads nor copies
`keys/radicle`, and it never exports `RAD_PASSPHRASE` to the reviewed offline
CLI. Private key and passphrase handling remains confined to explicit signer
commands.

## Node, operator, and availability boundary

Node views are replicas and verifiers, not voters. Node count and operator
count provide zero governance weight. Multiple processes under one disclosed
operator may satisfy the first trial's three-node replication model, while
remaining one shared operator failure domain.

Every configured checkpoint-proof view must agree before archival. Portable
proofs against the canonical state root, rather than replica count, authenticate
the checkpoint stake and identity state. A receipt proves retrieval and checks
at one time; it does not prove future availability or independent operation.

## Version and deployment boundary

The hash-locked 0.6.1 helper remains the only authorized epoch-235 input
capture path. The already distributed 0.6.2 security RC3 remains immutable
historical evidence, but its reducer implements the superseded identity-count
majority gate and must not settle a ballot under this 0.6.3 rule.

Source 0.6.3 is local and unpublished until an exact artifact manifest and a
separate deployment/distribution plan are reviewed and approved. This policy
does not authorize signing, broadcasting, pinning, posting, node changes, or
access to any private key.
