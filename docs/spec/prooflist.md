# Compact ProofList encoding

The media type `application/vnd.malt.prooflist.v1` carries the response to
one `malt.authentication/5` request. A recipient needs that exact request,
including its independently selected Root and ordered original labels. Core
exposes `protocol.EncodeProofList` and `protocol.DecodeProofList`. After
decoding, call `authentication.Verify` with the original request before
using a target, absence or count. The [logical query result](authentication-contracts.md)
also has a JSON projection for SDKs and offline verification.

## Wire order

An unsigned integer uses minimal unsigned LEB128. A blob contains its byte
length as an unsigned integer followed by those bytes. A CID uses its complete
self-delimiting binary CID encoding. A raw commitment and a witness each
have a width fixed by the current Root's profile. All records are concatenated.
Truncation, extra bytes, overlong integers, unknown tags and inconsistent
record counts are errors. A ProofList is limited to 96 MiB.

1. Write the traversal outcome. Integer 0 means all requested steps succeeded.
   Integer 1 is followed by the zero-based index of the first absent step.
2. For each visited step in request order, write the target CID if present,
   then its binding proof. An absent step ends the response. Start at the
   request Root, advance to each authenticated target, and read the descriptor
   from each new Root. The resolved target is the last target, or the original
   Root for a zero-step traversal.
3. Successful resolve ends here. For a binding request, write presence
   (0 or 1), the target CID if present, and its binding proof. For a range,
   write the List's metadata-only bounds proof for index UINT64_MAX. Then
   write presence, optional target and binding proof for each index in the
   requested half-open interval. The end defaults to the metadata count.
   Range segments share the bounds proof's metadata and its opening.
   The decoded per-segment metadata and primitive metadata proof together
   are limited to 96 MiB summed over the range.

## Binding proof

The first integer is the number of vector nodes on the selected path.
Visit them from root to terminal node. Derive the selector from the original
label and the current Root's derivation profile. Use the Map radix digits or
the List geometry defined by the [commitment encoding](commitment-proof-encoding.md).

- A List root carries a metadata cell as a blob and a slot-zero witness,
  except when a range has already supplied both. An out-of-bounds proof
  consists solely of this root node.
- At each nonterminal node, write the raw child commitment followed by the
  witness for the selected slot. Reconstruct the child reference from the
  parent's layout and commitment profile.
- At a present terminal node, write the witness. Reconstruct the cell from
  the request label and target for a Map, or the target for a List.
- At an absent Map terminal, write a blob containing the complete foreign
  leaf or zero bytes for an empty slot, followed by the witness. The verifier
  checks the foreign leaf's route and label. At an in-bounds absent List
  terminal, the cell is empty and the record contains only its witness.

KZG4096 uses a 48-byte child commitment and a 48-byte point per opening.
Restore the primitive's 32-byte value using the profile's cell-to-scalar
mapping and append the derived four-byte slot. IPA256 uses a 32-byte child
commitment and a 544-byte single-index witness (eight pairs of points and
the final scalar). Restore the eight-round header and the derived slot.
Distinct openings on a path are checked against their respective commitments.

For a present KZG Map step of height `h`, binding evidence occupies
`uvarintSize(h) + 48*(h-1) + 48*h` bytes. The enclosing traversal carries
the target CID once. A zero-step resolve has the single byte `00`.
For the corpus's `profile-1.opaque-label` binding, the byte prefix is
`00 01 01 55 00 00 01`, followed by the 48-byte point from its primitive
proof. The KZG and IPA fixtures in the protocol tests fix the complete binary
encoding and reconstruct the original typed evidence for both profiles.
