# HTTP API Routing

MALT core defines transport-neutral resolve/read profiles and JSON Schemas, not
HTTP service routes. See [Resolve and read contracts](./resolve-read-contracts.md).

The current managed HTTP API, including route naming, authentication, CORS,
limits, CAS access, mutation execution, errors, and deployment policy, is owned
and documented by `DeWebProtocol/gateway`. Client-local daemon routes are owned
by the MALT local runtime, currently published as
`DeWebProtocol/malt-client` during the repository migration.

This routing page is retained so historical MIPs and release notes do not point
to a missing document; it is not a normative HTTP specification.
