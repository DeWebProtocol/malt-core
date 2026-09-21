# Threat model

The trusted inputs are the caller-selected complete Root and intended typed
query. The executor, materializer, cache, network, response, and payload source
are untrusted. The local verifier uses installed exact cryptographic profiles
and deterministic input rules, with no network or storage lookup.

## Query attacks

Verification binds profile, complete Root, explicit ordered steps, final
operation, presence/absence, target, and all primitive openings. Replacing a
Root, key, selector, index, range, target, metadata value, or traversal prefix
must fail. A valid proof for a server-selected request does not establish the
client's intended claim.

Missing traversal evidence authenticates only the first failed step after the
verified prefix. It cannot claim the remaining suffix was evaluated. Backend
unavailability, malformed inputs, corrupt storage, and I/O errors must not be
reported as authenticated absence. No implicit payload redirect or longest-
prefix regrouping changes the client's query.

Strict current JSON decoding rejects unknown/case-mismatched/duplicate fields,
retired profiles, trailing data, and oversized/deep documents. Each Root must
name installed exact input and VC profiles; neither byte length nor an
application default overrides that identity.

## Materialization and writers

External complete candidates undergo Root-bound validation, including closed
reachable node sets and original input interpretation. Untrusted node storage
cannot grant ownership or bypass cryptographic checks. Owned immutable nodes
may be reused only through the tree's internal construction capability.
Session limits bound retained candidate count and conservative state charge;
opaque local handles never authenticate a portable statement.

Batches preserve dependency order and exact locally computed candidates.
Receipts match transaction, base, final Root, complete batch digest, and a
nonempty declared durability boundary. A receipt is not a signature, portable
state-transition proof, authorization decision, publication guarantee, or
trusted-root promotion. Those decisions belong to the service and client.

## Payloads, availability, and freshness

Relation proofs authenticate CIDs. Clients must hash fetched payload/manifest
bytes against those CIDs and bind range segments and geometry to authenticated
metadata. Cryptographically valid old Roots remain valid; freshness and
accepted/candidate Root policy are external. Authentication does not prove
remote availability, recoverability, or erasure.

Application path normalization, UnixFS manifests, encrypted chunk profiles,
tenancy, permission checks, durable transactions, HTTP, and trusted-root
storage are outside Core. See [architecture](../../ARCHITECTURE.md).
