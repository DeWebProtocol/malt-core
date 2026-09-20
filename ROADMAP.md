# MALT Core roadmap

The current source provides one typed authentication chain: deterministic input
rules, a coordinate-only Prefix/Positional tree, exact KZG/IPA profiles,
explicit graph traversal, independent local verification, immutable writers,
and ordered candidate batches with exact materialization receipts.

Further protocol work requires explicit design and conformance review:

1. Portable state-transition witnesses; current candidates/receipts do not
   establish such a proof.
2. Partial authenticated update views; current cold import/export remains a
   complete candidate boundary.
3. Variable-size Positional range evidence and native aggregated openings.
4. Independent language implementations checked against exact frozen corpora.

Core owns none of the service, persistence, application, or trust policies in
Gateway/runtime. Malt-ts owns browser APIs and exact published-Core assets;
malt-evaluation owns measurement/provenance, and malt-paper owns manuscripts.
Release adoption is separate from source migration. Historical milestones are
recorded in `CHANGELOG.md` and `docs/releases/`.
