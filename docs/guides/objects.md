# Constructing state with Objects

`sdk/object` lets an application construct a DAG with ordinary Go references.
An Object is one vertex; each reference to a child is one outgoing arc. Calling
the root Object's `Commit` commits children before their parents and returns
the root CID.

```go
type Object interface {
    Payload() cid.Cid
    Config() object.CommitConfig
    Commit(context.Context) (cid.Cid, error)
}
```

`Immutable` contains an owned copy of raw bytes and returns an ordinary
CIDv1 with the raw codec and SHA-256 multihash. `Map` returns a Prefix MALT
Root. `List` holds dense, zero-based references and returns a Positional Root.
`MapConfig(profile)` and `ListConfig(profile)` select the authentication layout
and coordinate derivation; each accepts either `maltcid.IPA256` or
`maltcid.KZG4096`. Install the corresponding commitment/proving implementations
in the engine you pass to the constructors. The Object package imports no
concrete commitment backend.

The [complete example](../../examples/objects/main.go) builds an object graph,
commits it, collects its ArcSets and content blocks, proves a traversal, changes
a nested reference, and independently verifies both versions:

```sh
go run ./examples/objects
```

## Map references

Given a configured `*engine.Engine` named `e`:

```go
content, err := object.NewImmutable([]byte("hello"))
if err != nil {
    return err
}
root, err := object.NewMap(e, object.MapConfig(maltcid.IPA256))
if err != nil {
    return err
}
if err := root.Set([]byte("greeting"), content); err != nil {
    return err
}
rootCID, err := root.Commit(ctx)
if err != nil {
    return err
}
fmt.Println(rootCID)
```

`Set` copies the label and retains the Object reference. `Get` returns that
reference. `Delete` removes it. Labels are opaque bytes; empty and binary labels
are supported, but a nil label is rejected. No path normalization or splitting
occurs. For a Direct Prefix configuration, every label must already contain
exactly 32 key bytes.

## List references

`NewList(e, object.ListConfig(maltcid.KZG4096))` selects Positional + KZG.
Choose `maltcid.IPA256` for the same container with IPA. `Append` appends child
references, `Set` replaces an existing index, and `Remove` shifts all following
references down by one. Invalid indices and nil children are errors.

List indices are zero-based integers. The corresponding authentication query
label is `coordinate.EncodeIndex(uint64(index))`, which contains eight unsigned
big-endian bytes. Decimal text such as `[]byte("0")` is not that label. List
containers do not infer byte-range measurements from their children.

## Struct tags

Embed `*object.Base` and provide a Commit method that passes the **outer** struct
to `CommitTagged`:

```go
type Document struct {
    *object.Base
    Cover object.Object `malt:"cover"`
    Parts *object.List  `malt:"parts,omitempty"`
    Local string       // Not authenticated or serialized.
}

func (d *Document) Commit(ctx context.Context) (cid.Cid, error) {
    return d.Base.CommitTagged(ctx, d)
}
```

Initialize the Base with `object.NewBase(e, object.MapConfig(profile))`.
`CommitTagged` reads `Config()` and `Payload()` from the outer Object, including
overrides. A tagged field points to one child vertex; it is never flattened.
There is no required `Arcs()` method.

- Only explicitly tagged exported fields participate. Untagged fields and
  `malt:"-"` are ignored, including untagged embedded structs.
- Tagged fields must implement Object and contain a non-nil pointer.
  `omitempty` permits nil interfaces and typed nil pointers to be omitted.
- Labels must be explicit and nonempty; use Map for empty or binary labels.
  Duplicate labels, unknown tag options and tagged unexported fields are errors.
- A Base belongs to one Object. Keep Object pointers rather than copying
  mutable container values or sharing a Base between different vertices.

Embedding a Map or List reuses that container's behavior. Its promoted Commit
method still has the embedded container as its receiver; it does not inspect
new fields in the outer struct. For additional named arcs, use a tagged Prefix
struct with its own Base and place the container in a tagged child field.

## Payloads and immutable bytes

`Payload()` returns `cid.Undef` for an absent payload. An empty byte block has
a defined CID and is distinct from absence. An Immutable leaf returns its own
content CID from Payload and Commit. `Bytes()` returns a copy for application
storage or transport. Other immutable codecs can implement Object directly;
`CommitConfig.Content` describes their content-CID prefix.

For Map and tagged Prefix objects, `SetPayload(cid)` binds an already encoded
payload CID during Commit. Passing `cid.Undef` removes it. `PayloadLabel(config)`
returns the reserved label for proving this binding: `@payload` with SHA256
derivation, or the canonical SHA256-derived coordinate of `@payload` with Direct
derivation. Map.Set and struct tags cannot overwrite that reserved binding.
This is a convention of `sdk/object`; the authentication engine continues to
treat these labels as ordinary bytes.

This first List implementation has no independent payload: its Payload method
returns `cid.Undef`. It authenticates only the dense item references, using the
existing Positional encoding. Nonempty List payloads need a separate encoding
decision; no hidden wrapper vertex, reserved list index, or metadata extension
is introduced here.

## Commit, prove, update, verify

Each top-level Commit traverses current references. Changing a child field or
replacing a nested Map reference is picked up by the next root Commit. With an
unchanged configuration, the Object passes its current ArcSet to the retained
`authentication.Writer.Update`: the input scan is complete, while authentication
node updates are incremental. A new configuration builds a new writer. There is
no persistent dirty flag. Within one Commit, a shared child pointer is committed
once. Cycles return `object.ErrCycle`.

Objects must not be mutated concurrently with Commit, or by a child while
Commit is traversing the graph. Custom recursive implementations must propagate
the supplied context; the built-in containers and CommitTagged cooperate in
cycle detection, shared-child memoization and snapshot staging. A custom Commit
method should finish fallible preparation before calling its helper and return
the helper's result directly, as in the Document example above.

`CID()` returns the last successful authentication Commit result, or `cid.Undef`
before the first success. It does not indicate whether the current Object has
changed. `Writer()` returns that vertex's retained immutable
`*authentication.Writer`; it returns `ErrNotCommitted` before the first success.
Keep the writer if that particular ArcSet version is needed later. `Writer.State`
copies its labels, targets and configuration without exporting node vectors.

For proofs, export the collected ArcSet candidates described below and
materialize them into caller-owned authentication-node storage. Existing `engine.Prove`,
`traversal.ResolvePath`, and `authentication.Execute` then operate on those
nodes. Verification uses the independently selected Root and query, with no
access to the mutable Objects.

Each managed Object retains its last two successful snapshots: the Root,
configuration, ArcSet writer, and the exact committed child versions it used.
An independently committed child cannot change an existing parent's snapshot.
All new snapshots are staged until the outermost managed Commit succeeds. An
error or cancellation before confirmation preserves every prior snapshot and
delta, including those of children already visited, so retrying can collect the
same pending changes. This atomicity covers local SDK state within that Commit
scope; arbitrary custom side effects and storage writes are outside it.

## Collecting changes

After a successful Commit, `Map`, `List`, `Immutable`, and structs embedding
`Base` expose `Delta(ctx)`. It compares the last two committed graphs. Before
the first success it returns `ErrNotCommitted`; the first successful Commit is
compared with an empty graph. Reading Delta does not advance its baseline.

```go
rootCID, err := root.Commit(ctx)
if err != nil {
    return err
}
delta, err := root.Delta(ctx)
if err != nil {
    return err
}
fmt.Printf("%s: %d changed ArcSets, %d content blocks\n",
    rootCID, len(delta.ArcSets), len(delta.Blocks))

// nodes is caller-owned authentication-node storage.
for _, change := range delta.ArcSets {
    candidate, err := change.Export(ctx)
    if err != nil {
        return err
    }
    if err := authentication.Materialize(ctx, e, candidate, nodes); err != nil {
        return err
    }
}
// Retain delta.Blocks in application content storage and ensure that the
// dependencies listed in delta.External are available before publishing.
```

- `Before` and `After` identify the enclosing graph versions. `Before` is
  undefined for the first Commit. Committing an unchanged graph yields an
  empty delta with equal Roots.
- `ArcSets` contains changed or newly attached ArcSets, deduplicated by their
  new Root and ordered children before parents. Each item lists label additions,
  deletions and target replacements, sorted by label bytes. List removals are
  explicit binding deletions. Configuration changes can produce a new Root
  with no changed bindings. `Export(ctx)` produces a complete candidate on
  demand, with `Previous` set to this delta's `Before`.
- `Blocks` contains owned bytes and CIDs for newly referenced local Immutable
  leaves, deduplicated and sorted by CID bytes. Replacing a leaf adds its new
  content; renaming or removing an arc does not duplicate or delete content.
- `External` lists newly referenced CIDs for which the graph has no local
  bytes or ArcSet writer, deduplicated and sorted by CID bytes. This includes
  `SetPayload(cid)` and custom Objects that return a CID directly. A custom
  Object delegating to `Immutable.Commit(ctx)` participates in byte collection.
  A CID also supplied by a local Object is collected once with that local data.

The comparison uses the enclosing graph's history. If a child independently
commits A → B → C between parent commits, the parent's next delta compares the
child's A with C. Attaching an already committed subtree to a new parent collects
that subtree's full state and locally known bytes, even if its own last Commit
was a no-op. Roots and content already referenced anywhere in the previous
graph need no new write candidate.

Save the returned Delta until its writes have been handled. The next successful
Commit advances the local baseline, even for a no-op; it does not wait for a
remote acknowledgement. Returned labels and bytes belong to the caller, and
ArcSet exports remain tied to their immutable versions after later Commits.

These are write candidates relative to the previous local graph, not a report
of what a remote store lacks. There are no physical content-deletion commands:
other graphs and retained older Roots may still need those CIDs. Commit and
Delta perform no storage writes, root publication or trust promotion, and a
Delta is not a portable state-transition proof.
