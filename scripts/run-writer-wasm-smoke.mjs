import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [wasmPath, wasmExecPath, fixturePath, selectedBackend = "kzg", selectedProfile = ""] =
  process.argv.slice(2);
if (!wasmPath || !wasmExecPath || !fixturePath) {
  console.error(
    "usage: node run-writer-wasm-smoke.mjs <writer.wasm> <wasm_exec.js> <client-root-vectors.json> [kzg|ipa] [direct|compact|fast]",
  );
  process.exit(2);
}
if (!["kzg", "ipa"].includes(selectedBackend)) {
  throw new Error(`unsupported writer backend ${JSON.stringify(selectedBackend)}`);
}
if (selectedBackend === "kzg" ? selectedProfile !== "" : !["direct", "compact", "fast"].includes(selectedProfile)) {
  throw new Error(`unsupported writer target ${selectedBackend}/${selectedProfile}`);
}
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
const corpus = JSON.parse(await readFile(fixturePath, "utf8"));
if (
  corpus.schema_version !== "malt.client-root.conformance/v1" ||
  !Array.isArray(corpus.vectors) ||
  corpus.vectors.length === 0
) {
  throw new Error(`${fixturePath} is not a non-empty client-root v1 conformance corpus`);
}

await import(pathToFileURL(wasmExecPath).href);
if (typeof globalThis.Go !== "function") {
  throw new Error(`${wasmExecPath} did not install the Go WASM runtime`);
}

const go = new globalThis.Go();
go.argv = ["malt-writer.wasm", `--backend=${selectedBackend}`];
const wasm = await readFile(wasmPath);
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
let runtimeFailure;
void go.run(instance).catch((error) => {
  runtimeFailure = error;
});

const deadline = Date.now() + 120_000;
while (Date.now() < deadline) {
  if (runtimeFailure) {
    throw new Error(`Go WASM runtime failed: ${runtimeFailure}`);
  }
  if (
    globalThis.maltWriterReady &&
    typeof globalThis.maltComputeClientRootV1 === "function" &&
    typeof globalThis.maltWriterBootstrapSessionV1 === "function" &&
    typeof globalThis.maltWriterLoadSessionV1 === "function" &&
    typeof globalThis.maltWriterPrepareSessionV1 === "function" &&
    typeof globalThis.maltWriterGetPreparedResultV1 === "function" &&
    typeof globalThis.maltWriterValidateReceiptV1 === "function" &&
    typeof globalThis.maltWriterAcceptSessionReceiptV1 === "function" &&
    typeof globalThis.maltWriterDiscardSessionCandidateV1 === "function" &&
    typeof globalThis.maltWriterCloseSessionV1 === "function"
  ) {
    break;
  }
  await new Promise((resolve) => setTimeout(resolve, 10));
}
if (
  !globalThis.maltWriterReady ||
  typeof globalThis.maltComputeClientRootV1 !== "function" ||
  typeof globalThis.maltWriterBootstrapSessionV1 !== "function" ||
  typeof globalThis.maltWriterLoadSessionV1 !== "function" ||
  typeof globalThis.maltWriterPrepareSessionV1 !== "function" ||
  typeof globalThis.maltWriterGetPreparedResultV1 !== "function" ||
  typeof globalThis.maltWriterValidateReceiptV1 !== "function" ||
  typeof globalThis.maltWriterAcceptSessionReceiptV1 !== "function" ||
  typeof globalThis.maltWriterDiscardSessionCandidateV1 !== "function" ||
  typeof globalThis.maltWriterCloseSessionV1 !== "function"
) {
  throw new Error("timed out waiting for MALT writer globals");
}
if (globalThis.maltWriterInitError) {
  throw new Error(`MALT writer initialization failed: ${globalThis.maltWriterInitError}`);
}
if (globalThis.maltWriterLoadedBackend !== selectedBackend) {
  throw new Error(
    `MALT writer loaded backend ${JSON.stringify(globalThis.maltWriterLoadedBackend)}, expected ${JSON.stringify(selectedBackend)}`,
  );
}
if (globalThis.maltWriterLoadedProfile !== selectedProfile) {
  throw new Error(
    `MALT writer loaded profile ${JSON.stringify(globalThis.maltWriterLoadedProfile)}, expected ${JSON.stringify(selectedProfile)}`,
  );
}

let rejectedStrings = false;
try {
  await globalThis.maltComputeClientRootV1("smoke", "{}", "{}");
} catch {
  rejectedStrings = true;
}
if (!rejectedStrings) {
  throw new Error("writer accepted JSON strings instead of bounded Uint8Arrays");
}

const encoder = new TextEncoder();
const hostileLength = new Proxy(encoder.encode("smoke"), {
  get(target, property) {
    if (property === "byteLength") {
      return -1;
    }
    return Reflect.get(target, property, target);
  },
});
let rejectedHostileLength = false;
try {
  await globalThis.maltComputeClientRootV1(
    hostileLength,
    encoder.encode("{}"),
    encoder.encode("{}"),
  );
} catch {
  rejectedHostileLength = true;
}
if (!rejectedHostileLength) {
  throw new Error("writer accepted a proxied Uint8Array with hostile length metadata");
}

if (selectedBackend === "kzg") {
  const oversizedJSON = new Uint8Array(64 * 1024 * 1024 + 1);
  let rejectedOversized = false;
  try {
    await globalThis.maltComputeClientRootV1(
      encoder.encode("smoke"),
      oversizedJSON,
      encoder.encode("{}"),
    );
  } catch {
    rejectedOversized = true;
  }
  if (!rejectedOversized) {
    throw new Error("writer accepted JSON above the 64 MiB wire limit");
  }
}

let rejectedInvalidJSON = false;
try {
  await globalThis.maltComputeClientRootV1(
    encoder.encode("smoke"),
    encoder.encode("{}"),
    encoder.encode("{}"),
  );
} catch {
  rejectedInvalidJSON = true;
}
if (!rejectedInvalidJSON) {
  throw new Error("writer accepted invalid update-view and semantic-intent JSON");
}

const bootstrapView = JSON.parse(await globalThis.maltWriterBootstrapSessionV1());
if (
  bootstrapView.profile !== "malt.update-view/v1" ||
  bootstrapView.objects?.length !== 1 ||
  bootstrapView.objects[0]?.object_id !== "root" ||
  bootstrapView.objects[0]?.kind !== "map" ||
  bootstrapView.objects[0]?.entries?.length !== 0
) {
  throw new Error(`${selectedBackend} bootstrap did not return the canonical empty-map view`);
}
await globalThis.maltWriterCloseSessionV1();

const selectedVectors = corpus.vectors.filter(
  ({ backend }) => backend === selectedBackend,
);
const validFixtures = selectedVectors.filter(({ expected }) => expected?.valid === true);
const invalidFixtures = selectedVectors.filter(({ expected }) => expected?.valid === false);
if (validFixtures.length !== 1 || invalidFixtures.length === 0) {
  throw new Error(
    `selected ${validFixtures.length} valid and ${invalidFixtures.length} invalid vectors for ${selectedBackend}`,
  );
}
for (const fixture of invalidFixtures) {
  let rejected = false;
  try {
    await globalThis.maltComputeClientRootV1(
      encoder.encode(fixture.operation_id),
      encoder.encode(JSON.stringify(fixture.update_view)),
      encoder.encode(JSON.stringify(fixture.semantic_intent)),
    );
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error(`${fixture.id} was accepted, want rejection`);
  }
}
for (const fixture of validFixtures) {
  const operationID = encoder.encode(fixture.operation_id);
  Object.defineProperty(operationID, "byteLength", { value: -1 });
  const updateView = encoder.encode(JSON.stringify(fixture.update_view));
  const semanticIntent = encoder.encode(JSON.stringify(fixture.semantic_intent));
  for (const input of [operationID, updateView, semanticIntent]) {
    Object.defineProperty(input, "subarray", {
      value() {
        throw new Error("caller-controlled subarray must not be invoked");
      },
    });
  }
  const resultJSON = await globalThis.maltComputeClientRootV1(
    operationID,
    updateView,
    semanticIntent,
  );
  const result = JSON.parse(resultJSON);
  if (result.profile !== "malt.writer-compute-result/v2") {
    throw new Error(`unexpected writer result profile ${JSON.stringify(result.profile)}`);
  }
  if (result.bundle.operation_id !== fixture.operation_id) {
    throw new Error(`unexpected operation ID for ${fixture.backend}`);
  }
  assert.deepStrictEqual(
    result.bundle,
    fixture.expected.bundle,
    `${fixture.backend} WASM bundle differs from the native canonical bundle`,
  );
  assert.deepStrictEqual(
    result.next_view,
    fixture.expected.next_view,
    `${fixture.backend} WASM next view differs from the native canonical next view`,
  );
  assert.deepStrictEqual(
    result.materialization,
    fixture.expected.materialization,
    `${fixture.backend} WASM materialization differs from the native canonical materialization`,
  );
  assert.deepStrictEqual(
    Object.keys(result.metrics).sort(),
    [
      "bundle_validation_ns",
      "commitment_update_ns",
      "digest_ns",
      "expected_root_encoding_ns",
      "intent_normalization_ns",
      "next_view_ns",
      "root_computation_ns",
      "total_ns",
      "view_normalization_ns",
    ],
    `${fixture.backend} result has an unexpected metrics shape`,
  );
  for (const [name, value] of Object.entries(result.metrics)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${fixture.backend} metric ${name} is not a non-negative safe integer`);
    }
  }

  const sessionView = encoder.encode(JSON.stringify(fixture.update_view));
  const loadedRoot = await globalThis.maltWriterLoadSessionV1(sessionView);
  if (loadedRoot !== fixture.update_view.base_root) {
    throw new Error(
      `${fixture.backend} session loaded ${loadedRoot}, expected ${fixture.update_view.base_root}`,
    );
  }
  const sessionOperationID = encoder.encode(fixture.operation_id);
  const sessionIntent = encoder.encode(JSON.stringify(fixture.semantic_intent));
  const candidate = await globalThis.maltWriterPrepareSessionV1(
    sessionOperationID,
    sessionIntent,
  );
  if (candidate !== fixture.expected.bundle.candidate) {
    throw new Error(
      `${fixture.backend} session prepared ${candidate}, expected ${fixture.expected.bundle.candidate}`,
    );
  }
  const preparedJSON = await globalThis.maltWriterGetPreparedResultV1(
    sessionOperationID,
  );
  assert.equal(
    await globalThis.maltWriterGetPreparedResultV1(sessionOperationID),
    preparedJSON,
    `${fixture.backend} repeated prepared-result lookup changed bytes`,
  );
  const prepared = JSON.parse(preparedJSON);
  assert.deepStrictEqual(
    prepared.bundle,
    fixture.expected.bundle,
    `${fixture.backend} session bundle differs from the stateless reference`,
  );
  assert.deepStrictEqual(
    prepared.next_view,
    fixture.expected.next_view,
    `${fixture.backend} session next view differs from the stateless reference`,
  );
  assert.deepStrictEqual(
    prepared.materialization,
    fixture.expected.materialization,
    `${fixture.backend} session materialization differs from the stateless reference`,
  );

  const discarded = await globalThis.maltWriterDiscardSessionCandidateV1(
    sessionOperationID,
  );
  if (discarded !== fixture.operation_id) {
    throw new Error(`${fixture.backend} session discarded the wrong operation`);
  }
  let rejectedDiscardedResult = false;
  try {
    await globalThis.maltWriterGetPreparedResultV1(sessionOperationID);
  } catch {
    rejectedDiscardedResult = true;
  }
  if (!rejectedDiscardedResult) {
    throw new Error(`${fixture.backend} session returned a discarded prepared result`);
  }
  const candidateAfterDiscard = await globalThis.maltWriterPrepareSessionV1(
    sessionOperationID,
    sessionIntent,
  );
  assert.equal(
    candidateAfterDiscard,
    fixture.expected.bundle.candidate,
    `${fixture.backend} re-prepared a different candidate after discard`,
  );
  const preparedAfterDiscardJSON = await globalThis.maltWriterGetPreparedResultV1(
    sessionOperationID,
  );
  const preparedAfterDiscard = JSON.parse(preparedAfterDiscardJSON);
  assert.deepStrictEqual(
    preparedAfterDiscard.bundle,
    fixture.expected.bundle,
    `${fixture.backend} re-prepared bundle differs from the reference`,
  );
  assert.deepStrictEqual(
    preparedAfterDiscard.next_view,
    fixture.expected.next_view,
    `${fixture.backend} re-prepared next view differs from the reference`,
  );
  assert.deepStrictEqual(
    preparedAfterDiscard.materialization,
    fixture.expected.materialization,
    `${fixture.backend} re-prepared materialization differs from the reference`,
  );
  const expectedReceiptJSON = encoder.encode(JSON.stringify(fixture.expected.receipt));
  const validatedRoot = await globalThis.maltWriterValidateReceiptV1(
    encoder.encode(preparedAfterDiscardJSON),
    expectedReceiptJSON,
  );
  if (validatedRoot !== fixture.expected.bundle.candidate) {
    throw new Error(
      `${fixture.backend} stateless receipt validation returned ${validatedRoot}, expected ${fixture.expected.bundle.candidate}`,
    );
  }
  const acceptedRoot = await globalThis.maltWriterAcceptSessionReceiptV1(
    sessionOperationID,
    expectedReceiptJSON,
  );
  if (acceptedRoot !== fixture.expected.bundle.candidate) {
    throw new Error(
      `${fixture.backend} session accepted ${acceptedRoot}, expected ${fixture.expected.bundle.candidate}`,
    );
  }

  let rejectedStaleIntent = false;
  try {
    await globalThis.maltWriterPrepareSessionV1(
      encoder.encode(`${fixture.operation_id}-stale`),
      sessionIntent,
    );
  } catch {
    rejectedStaleIntent = true;
  }
  if (!rejectedStaleIntent) {
    throw new Error(`${fixture.backend} session accepted an intent at the stale base`);
  }
  await globalThis.maltWriterCloseSessionV1();
  let rejectedClosedPrepare = false;
  try {
    await globalThis.maltWriterPrepareSessionV1(
      encoder.encode(`${fixture.operation_id}-closed`),
      sessionIntent,
    );
  } catch {
    rejectedClosedPrepare = true;
  }
  if (!rejectedClosedPrepare) {
    throw new Error(`${fixture.backend} session prepared after close`);
  }
  const reloadedRoot = await globalThis.maltWriterLoadSessionV1(
    encoder.encode(JSON.stringify(fixture.update_view)),
  );
  assert.equal(
    reloadedRoot,
    fixture.update_view.base_root,
    `${fixture.backend} Worker could not load a new session after close`,
  );
  await globalThis.maltWriterCloseSessionV1();
  await globalThis.maltWriterCloseSessionV1();
}
console.log(
  `WASM ${selectedBackend} client-root conformance passed (${validFixtures.length} accepted; ${invalidFixtures.length} rejected)`,
);
process.exit(0);
