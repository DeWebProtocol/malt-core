# Data Authentication Background

MALT is a data authentication layer. It helps a client check that application
data returned by a gateway, cache, storage service, or local index matches a
trusted root.

This page explains the progression from hashes to Merkle DAGs, then shows where
MALT changes the model.

## Hashes Authenticate One Object

A cryptographic hash authenticates one byte string.

```text
bytes -> hash(bytes) -> content identifier
```

If a client already trusts the expected hash, it can fetch the bytes from an
untrusted location, hash them again, and compare the result. A mismatch means
the bytes were corrupted, substituted, or not the expected object.

This works well for a single immutable object. It does not by itself describe
how to authenticate relationships among many objects, such as a directory tree,
an application manifest, an agent-memory namespace, or an ordered log.

## Merkle Trees Authenticate a Set

A Merkle tree authenticates many leaves by hashing them into parent nodes until
there is one root hash.

```text
        root
       /    \
   node      node
   /  \      /  \
 leaf leaf  leaf leaf
```

To verify one leaf, the client needs the leaf bytes and the sibling hashes along
the path to the root. The client recomputes each parent hash and checks that the
final value equals the trusted root.

Merkle trees are efficient for membership proofs over ordered or indexed sets.
They also make the root change whenever a leaf or intermediate node changes.

## Merkle DAGs Authenticate Linked Objects

A Merkle DAG generalizes this idea to content-addressed objects that may link to
other content-addressed objects. A parent object contains child references, and
the parent's CID commits to both its own content and those references.

```text
root CID
   |
 parent object
   |
 child object
   |
 target object
```

This prevents tampering because every object is addressed by its hash. To
verify a traversal from a trusted root CID to a target object, the client checks
that each fetched object hashes to its CID and that each parent object contains
the next child reference.

That model is powerful for immutable content-addressed structures, but it also
couples several things to the object boundary:

- the object payload
- the links used for traversal
- the proof material needed to verify traversal
- the cost of reference updates
- the data layout exposed to readers

If a child reference changes, the parent object's CID changes. That change can
propagate toward the root. If a client wants to verify a path without trusting a
gateway, the linked objects along the traversal path are also part of the
evidence the client needs.

## MALT Authenticates Graph Arcs Separately

MALT is a general graph data-authentication system whose authentication
granularity is an arc rather than a storage block. It keeps payload bytes in
ordinary content-addressed storage, while vector-commitment backends commit to
and prove typed map/list relations under independent roots.

```text
trusted MALT root + typed arc query
        |
        v
result + ProofList
```

The client verifies `trusted root + query -> result` with a dedicated
`ProofList`. Payload objects remain ordinary CAS data; ArcTable, caches,
daemons, and gateways remain untrusted execution state.

MALT separates three concerns that an implicit Merkle-DAG link couples at the
block boundary:

- payload storage in CAS
- relation authentication through typed arc commitments and proofs
- execution and access through application models, indexes, daemons, gateways, or clients

This separation gives MALT four core advantages:

- **Dedicated proof material:** verification uses `ProofList` evidence instead
  of the Merkle-DAG traversal object chain.
- **Direct application-shaped reads:** clients use typed arc queries; application models
  such as UnixFS may compose them into familiar path operations.
- **Transport-neutral verification:** operation-specific results carry
  ProofList evidence while payload bytes can be fetched from ordinary CAS.
- **Lower rewrite amplification:** relationship updates advance MALT structure
  roots without rewriting unrelated payload objects.

## Where To Go Next

- For a direct comparison, read [Merkle DAG vs MALT](./merkle-dag-vs-malt.md).
- For exact proof fields and operation binding rules, read
  [typed query evidence](../spec/authentication-contracts.md).
- For the current input and tree model, read
  [authentication model](../spec/authentication-inputs.md).
- For the portable core contract, read
  [MIP-1011](../mips/mip-1011-arc-authentication-core-contract.md).
