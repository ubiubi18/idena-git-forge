# Limitations and explicit boundaries

## Canonical branch presentation

The forge's canonical branch is:

```text
refs/idena/epoch/<epoch>/canonical
```

The reducer ignores Radicle delegates and ordinary `refs/heads/*` for authority.
Stock Radicle tools may need a small adapter to display this ref as their
default branch. That adapter would affect presentation only.

## Radicle transport

All Radicle releases available on 2026-10-30 use a transport that the project
disclosed as unencrypted and vulnerable to peer-ID impersonation. This forge
therefore disables Radicle node, sync, fetch, clone, and seed commands. It uses
Radicle only as a local storage and COB implementation and uses Idena IPFS for
content transport.

Private repositories are unsupported. Do not put private content into a Radicle
storage bundle or Idena IPFS. The full policy and upgrade gate are in
[SECURITY_TRANSPORT.md](SECURITY_TRANSPORT.md).

## Content availability

Idena consensus orders the complete tagged action bytes inline. It cannot prove
that a node will keep the larger referenced IPFS blocks online. The publisher
and mirrors must seed:

- the signed Idena anchor;
- the exact Radicle storage bundle;
- the patch diff;
- current open issue and patch data; and
- canonical Git history.

Unrelated Idena IPFS transactions are not fetched during action discovery and
cannot block settlement. Missing content referenced by a recognized forge
action leaves settlement pending. A compliant client must not reject that
action locally and choose another PR, because selective availability would then
let honest replicas derive different canonical heads. The recognized action
still consumes its deterministic per-identity quota slot. Once every required
CID is available and valid, clients can retry the same authenticated history.

This fail-closed rule protects safety but leaves a liveness limitation: an
eligible identity can reference a valid CID and withhold its bytes, delaying
that epoch and every later replay. Idena currently has no consensus-native
proof of IPFS availability. Removing this denial-of-service boundary requires
a protocol update such as deterministic on-chain chunks or a consensus-bound
availability certificate; a local timeout is not safe because nodes can see
different content.

During discovery, verifier nodes retain only content-independent recognized
actions and their referenced objects with an epoch-bounded lease. This avoids
turning an identity-valid but Radicle-invalid action into an indefinite storage
allocation. After the checkpoint input and result are authenticated and
reproduced, `forge retain` promotes every accepted action and referenced object
to repository-scoped local retention and permanent local Idena IPFS pins.
Repository deletion sets `pruneAfterEpoch = deletionEpoch + 2`; `forge prune
--delete` refuses early deletion and preserves objects shared with another
active repository. Independent seeders are still required for network
availability. The chain can prove the deletion decision but cannot prove that
every replica actually retained or deleted its local copy.

Expired lease-bound objects are removed automatically after scanning and by
the explicit `forge gc` command, using the node's canonical current epoch. The
local pin index uses an operating-system file lock for cross-process mutation;
unsupported platforms fail closed instead of writing without a lock.

## Historical state window

`idena-go` retains a bounded number of committed state versions. The
`dna_epochCheckpoint` and identity-proof RPCs must be called while the
checkpoint version exists, normally immediately after the
`ValidationFinished` block. Clients can use the Idena indexer's historical
`DataWithProof` endpoint as a fallback; its proof is still checked against the
local checkpoint state root. `dna_epochCheckpoint` also returns an IAVL proof
for the global value containing the post-transition epoch. The archived epoch
and identity proofs remain useful after the node prunes its local trie;
archiving only the RPC's epoch number is insufficient. Checkpoint proof packets
therefore need replication and pinning. If the fallback omits a required proof,
the checkpoint fails instead of silently excluding that voter.

## Large repositories

A Radicle storage bundle can exceed a practical single IPFS request or
transaction-policy size. The current implementation treats one bundle CID as
the replication unit. A later parallel protocol update can add a deterministic
manifest of chunk CIDs without changing operation ordering.

The Idena JSON-RPC server also caps one HTTP request at 2 MiB. Because
`ipfs_add` carries object bytes as hexadecimal JSON, a single safely portable
raw object must be materially smaller than 1 MiB. The forge source archive is
small enough for one object, but current platform binaries and a fully vendored
offline source package are not. Their distribution therefore needs a manifest
of independently hashed raw chunks before it can honestly claim an
Idena-IPFS-only bootstrap. The prepared distribution manifest is local and no
distribution artifact has been pinned or announced yet.

## UI publication

The first Idena IPFS preview implementation exports one self-contained HTML
file, including every available diff. It fails when the result exceeds the
900,000-byte current Idena Desktop publishing limit. A later chunked manifest
or directory-capable Idena IPFS add path can remove that limit.

`forge share-ui` pins the file locally and emits an `idena.social` post plan.
It cannot send the `makePost` call. The companion social UI recognizes
`idena-radicle://<CID>`, retrieves the HTML through the local Idena node, and
renders it only in a sandboxed, non-networked iframe. HTML previews are static
so the sandbox does not need script permission. Posting the saved plan remains
a separately approved action through an Idena client.

## Network activation

Production replay is bound to Idena mainnet activation epoch 235 and rejects a
history suffix or an epoch gap. A devnet or future network therefore needs a
reviewed network profile with its own compiled activation point; the CLI does
not accept a caller-selected activation epoch.

## Finality

The checkpoint is a canonical `ValidationFinished` block reported by the
client's synchronized node. Idena's RPC does not expose a separate "finalized"
height field. A reorg above the checkpoint invalidates the computed result and
requires replay against the new canonical block.

## Reviews

Radicle stores one review per actor per exact revision. Review edits use the
`review.edit` COB action and remain attached to the same review ID. The bridge
supports the latest `review.edit` operation, but the stock 1.10.3 CLI does not
yet expose an edit command; such edits require Radicle's typed COB API or a
reviewed CLI extension.

## Mainnet

The earlier mainnet trial did not produce an authenticated checkpoint archive
or a settled governed pull request. Its identity-bound publication artifacts,
node labels, receipts, and exact repository history are intentionally omitted
from this privacy-safe source handoff. A future trial must re-anchor at a new
checkpoint after proof-RPC capability is restored. The earlier bounded trial
is not evidence that the forge as a whole is production-ready.
