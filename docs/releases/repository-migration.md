# Core Repository And Module Migration

The application-neutral MALT SDK moved from `DeWebProtocol/malt` to
`DeWebProtocol/malt-core` for the `v0.0.7` release.

## Current Coordinates

```text
Repository: https://github.com/DeWebProtocol/malt-core
Go module:  github.com/dewebprotocol/malt-core
Version:    v0.0.7
```

Go consumers must update both the required module and source imports:

```bash
go get github.com/dewebprotocol/malt-core@v0.0.7
go mod tidy
```

The former import path `github.com/dewebprotocol/malt` names historical Core
versions only. It is not a forwarding Go module for `malt-core` and must not be
used for new builds.

## Preserved History

The repository rename preserved the complete Core Git object database and all
published tags, GitHub Releases, and release assets. Historical Core versions
remain valid records of the software published under their original module
path. They have not been deleted, retracted, moved, or retagged.

The old GitHub repository slug is reserved for the separately versioned MALT
local runtime. Once that slug is reused, GitHub cannot redirect old repository
URLs to `malt-core`. References to historical Core source and releases should
therefore use the `DeWebProtocol/malt-core` repository URL.

The local runtime initially retains the independent Go module path
`github.com/dewebprotocol/malt-client`. Any later runtime module namespace
change is a separate pre-v1 migration and does not move or replace Core tags.

## Protocol Compatibility

The repository and module rename does not change MALT wire identity. Relative
to `v0.0.7-rc.5`, `v0.0.7` preserves:

- Root and CID codecs;
- commitment parameters, commitments, openings, and transcripts;
- ProofList and proof encodings;
- Resolve, Read, Map-proof, client-root, mutation, and receipt schemas;
- serialized request, result, mutation, and receipt formats; and
- conformance vector contents.

The separate `v0.0.6` to `v0.0.7` compatibility limits remain documented in
the [v0.0.7 release notes](./v0.0.7.md).
