# Experimental compact hash authentication

`auth/experimental/hashtrie` is a SHA-256 compressed binary Patricia tree for
controlled evaluation. It authenticates complete canonical key/index
coordinates and complete CID targets, including exact membership and absence.
It is not registered as a native commitment profile and does not borrow a KZG,
IPA, MALT Root or ProofList identity. Native `maltcid.ParseRoot` rejects its
reference carrier. Native Root `V=0` policy and serialization are unchanged.

Leaves bind the coordinate kind, complete 8/32-byte coordinate and full target
CID. Branches bind the split bit, canonical shared prefix and both child
digests. Node and routing hashes use distinct domain-separated SHA-256 inputs.
An absence witness terminates at an empty tree, a different complete leaf or a
committed divergent compressed prefix. Missing materialization is an error.
No backend lookup failure can become an authenticated absence result.

Witnesses contain one sibling and prefix per traversed compact branch. They
do not contain a full sparse vector or a list of every map binding. Verification
depends only on a caller-selected experimental root, exact typed coordinate
and witness. Application labels and derivation remain outside authentication.
An application/evaluation binder must freeze the same label derivation and
target-CID construction used by its native comparison.

The node adapter consumes existing narrow `materializer.Lookup` and
`materializer.Updater` capabilities. Canonical experimental node bytes use the
same internal identity-CID carrier convention as native encoded vectors, under
a separate experimental path prefix and node-owner identity. Storage, CAS,
transactions, persistence, checkpoint, cache and publication policy remain
caller-owned. This permits a shared ArcTable/KV adapter without defining a
second durable store inside Core. Natural branch geometry, key lengths, row
counts and serialization costs remain measurable differences.

`Apply` checks the complete before target against the selected root and writes
only newly derived compact path nodes. Deletion collapses singleton branches;
untouched nodes and old roots remain immutable. A returned root is an execution
result, not a portable transition, trust, publication or freshness proof.

This package supplies the algorithm needed by the strong-hash ablation. It does
not itself establish same-store product measurements, persistent proof-state
costs, online service, graph composition, browser compatibility or release
eligibility. Those require explicit evaluator/Gateway/runtime adapters and
reviewed experiment provenance. Experimental source must remain identified as
such until reviewed; it must not silently replace an existing publication pin.
