# Upstream basis

The implementation was checked against these public repository revisions on
2026-10-30:

| Repository | Commit |
| --- | --- |
| `truongfelix/idena-go` | `2f0b9fa174cc53c08dd311c12b5ed43315ea9000` |
| `truongfelix/idena-mobile` | `30ebe8878c6abacbd61a1650750950c9a16cf92b` |
| `truongfelix/idena-desktop` | `14ff2a58c3ede088ddd52b543dfcd3bd2bf39533` |
| `truongfelix/idena-profile` | `82cfee2576fdc64f07305b0dcebdbf620c32d6ed` |
| `idena-network/idena-indexer-api` | `a018cebba8fc42a6b2eda3a11b303d26ea7abb5c` |
| `radicle-dev/heartwood` | `244a8b6fca9ebffe7543cdb2b486a78c7df9cf78` |
| Radicle stock source/compatibility baseline | `1.10.3` |
| Reviewed delegate-free Radicle executable | Darwin/ARM64 `244a8b6-dirty`, SHA-256 `1fe1b03c6ed77921370be44d769e559b4e9a5163e1cc60e515310363dd3ca228` |

Radicle `1.10.3` is the latest stock release observed at the time of this
record. It was used as a source and compatibility baseline but is not an
accepted governance-runtime executable because its repository identity retains
delegate authority. The runtime accepts only the reviewed delegate-free fork
and its separately pinned binary digest.
The 2026-09-23 disclosure states that the node transport is unencrypted and
does not reliably authenticate peer Node IDs in all released versions. This
repository therefore uses only Radicle's local storage and COB behavior and
keeps the node transport disabled. See
[SECURITY_TRANSPORT.md](SECURITY_TRANSPORT.md).

Relevant native behavior:

- `api/dna_api.go` exposes `dna_sign` with `doubleHash` and `prefix` formats.
- `api/dna_api.go` exposes `dna_storeToIpfs`.
- `blockchain/rewards.go` uses `stake^0.9`.
- `blockchain/blockchain.go` applies rewards and increments the epoch on a
  `ValidationFinished` block.
- `core/state/statedb.go` commits stake and identity state together in the
  main state tree.
- `core/appstate/appstate.go` can load historical state versions.
- The existing public RPC has no historical identity proof method.
- The indexer exposes epoch-scoped `DataWithProof` records whose
  `ValueWithProof` payload can be verified against the same checkpoint root.

`idena-profile` confirms the same underlying Idena contract and identity
conventions, but no existing repository contains a Git forge that could be
reused directly.

Radicle source and the official macOS ARM64 release binary were used only for
the forge, Git, issue, patch, review, label, and COB semantics. The governance
runtime does not connect to Radicle seeds or hosted services.
