# CID and wire format

Current MALT Roots use CIDv1 with codec
`0x300000 | (V << 12) | (L << 8) | AA`, abbreviated `0x30VLAA`.
`V=0` is required throughout pre-production. `L` selects the Prefix or Positional
authentication layout; `AA` selects the coordinate derivation profile.
Flat/compositional ArcSet organization is not encoded in the Root.
The codec integer is a minimal unsigned
varint, not a fixed four-byte prefix.

The identity multihash carries a multicommitment:

```text
uvarint(exact VC profile ID) || uvarint(commitment length) || commitment bytes
```

The full descriptor selects interpretation. The codec alone cannot select a
backend, and commitment length cannot infer one. `wire/maltcid.NewRoot` and
`ParseRoot` are the current constructors/reader. Historical semantic-kind
constructors and V2/V3 decoding are removed.

Only the MALT subrange `0x300000–0x30ffff` is considered for Root parsing.
Readers reject unsupported versions/layouts/profiles, invalid combinations,
nonminimal varints, non-identity hash wrappers, wrong commitment widths, and
trailing bytes. Execution additionally requires the exact derivation profile and
verification/commitment implementation to be installed.

Internal authentication references are `MN || 0x00 || byte(L) ||
multicommitment`. They name coordinate-based authentication nodes, not
application vertices, and omit AA. Application targets preserve their complete
Root or ordinary payload CID. Equal commitment bytes do not imply equal Root
or query semantics.

Payload CIDs retain their ordinary CAS meaning. Clients hash fetched bytes
against the authenticated target CID. Replacing an old Root prefix does not
migrate old authentication state; reconstruct the state and dependent parents.

See [derivation profiles and exact profiles](authentication-inputs.md),
[proof encoding](commitment-proof-encoding.md), and
[Root version policy](../policy/root-versioning.md).
