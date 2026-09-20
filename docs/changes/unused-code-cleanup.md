# Unused source API cleanup

This earlier cleanup stage is superseded by the
[typed authentication migration](typed-authentication-only.md). Its original
API mapping and validation record remain in
[the prior source revision](https://github.com/dewebprotocol/malt-core/blob/a4526f8751db403eaa2e1a7ac6add00b70ff2933/docs/changes/unused-code-cleanup.md).

Current callers use `sdk/authentication`, explicit typed queries, and ordered
candidate batches. Map/List adapters, string resolver, old client-root writer,
old proof envelopes, and forwarding/compatibility interfaces are removed.
