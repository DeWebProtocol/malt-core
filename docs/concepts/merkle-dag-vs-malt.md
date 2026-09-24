# Merkle DAG vs MALT

MALT keeps the useful part of content-addressed storage: immutable payload bytes
can still live in CAS blocks with ordinary CIDs. The difference is that MALT
does not use the Merkle-DAG object chain as the application proof path.

## Short Version

| Concern | Merkle DAG | MALT |
| --- | --- | --- |
| Authentication granularity | Parent/child links committed at block boundaries | Typed arcs committed independently from payload blocks |
| Payload storage | Immutable content-addressed objects | Ordinary immutable CAS payloads |
| Relationship authentication | Links embedded in parent object content | Typed bindings under Prefix/Positional Roots |
| Read shape | Traverse linked objects from a root CID | Query `trusted root + typed arc`; application models may expose paths |
| Proof material | Traversal objects and sibling or linked evidence | Dedicated typed authentication evidence |
| Trusted components | Traversed content-addressed object chain | Portable auth kernel; indexes and gateways remain untrusted |
| Network reads | Transport linked blocks or gateway responses | Carry operation-specific result/evidence plus separately fetched CID bytes |
| Update cost | Child-reference changes can propagate rootward | Structure roots advance without rewriting unrelated payload objects |

## Proof Material

In a Merkle DAG, each object CID commits to that object's bytes, including its
links. To verify a path, a client usually needs the linked object chain from
the trusted root to the target. Those intermediate objects are not just
payload; they are evidence for the traversal.

MALT separates the proof from the payload object chain. The verifier checks a
typed authentication evidence against a trusted MALT root, query, and result:

```text
authentication.Verify(engine, callerRequest, untrustedResult) -> valid / invalid
```

For a binding lookup, proof size depends on authenticated tree depth and the
selected commitment backend; it is not a universally fixed-size path proof. A response that intentionally combines
multiple semantic lookups or range segments carries the corresponding proof
steps, but the authentication evidence is still dedicated verifier evidence rather than the
Merkle-DAG traversal objects themselves.

## Direct Root And Typed Query Reads

Merkle-DAG readers normally traverse from object to object. A gateway can hide
that traversal, but then the client must either trust the gateway's answer or
fetch enough evidence to verify the traversal.

MALT's core read contract is root-relative and typed:

```text
Execute(AuthenticationRequest{Root, Steps, Operation}) -> AuthenticationResult
```

The application requests one authenticated relation, and the verifier checks
the result against the trusted root and query. An application model such as UnixFS can
compose primitive arc reads into a path without making Unix paths part of the
generic core.

## Transport And Payload Retrieval

Merkle DAGs can be transported over HTTP. The difference is what the client
must receive to verify the answer.

MALT transports carry operation-specific results and authentication evidence. A client may
then fetch authenticated payload CIDs from an HTTP CAS endpoint:

```text
typed authentication query -> target CID + authentication evidence
GET  /v1/cas/{target CID} -> payload bytes
```

The client verifies the relation evidence locally and hashes the payload bytes
against the authenticated CID. A gateway, CDN, or cache can serve either
response without becoming a correctness authority.

The operation contracts are documented in
[typed authentication contracts](../spec/authentication-contracts.md). HTTP route
behavior belongs to the gateway repository.

## Rewrite Amplification

In a Merkle DAG, changing a child reference changes the parent object's CID.
If that parent is linked from another parent, the change can propagate toward
the root. This is not a bug; it is how content-addressed identity authenticates
embedded links.

MALT moves mutable relationships into authenticated structure roots. Updating a
relationship advances the relevant MALT root, but unrelated payload objects can
keep their original CIDs.

MALT does not claim that updates are free. It replaces implicit
ancestor-rewrite cost with explicit, verifiable structure maintenance.

## What MALT Does Not Replace

MALT is not a replacement for IPFS, Filecoin, Kubo, S3, or object storage. It
can run above those systems. They provide payload storage and transport; MALT
provides authenticated mutable structure, proof generation, and verification
above payload objects.
