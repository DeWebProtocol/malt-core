import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [wasmPath, wasmExecPath, corpusPath, selectedBackend = "all", mapProofCorpusPath] =
  process.argv.slice(2);
if (!wasmPath || !wasmExecPath || !corpusPath) {
  console.error(
    "usage: node run-verifier-wasm-vectors.mjs <verifier.wasm> <wasm_exec.js> <resolve-read-vectors.json> [all|kzg|ipa] [map-proof-vectors.json]",
  );
  process.exit(2);
}
if (!["all", "kzg", "ipa"].includes(selectedBackend)) {
  throw new Error(`unsupported verifier backend ${JSON.stringify(selectedBackend)}`);
}

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

await import(pathToFileURL(wasmExecPath).href);
if (typeof globalThis.Go !== "function") {
  throw new Error(`${wasmExecPath} did not install the Go WASM runtime`);
}

const corpus = JSON.parse(await readFile(corpusPath, "utf8"));
if (
  corpus.schema_version !== "malt.resolve-read.conformance/v2" ||
  !Array.isArray(corpus.vectors) ||
  corpus.vectors.length === 0
) {
  throw new Error(`${corpusPath} is not a non-empty Resolve/Read v2 corpus`);
}
const mapProofCorpus = mapProofCorpusPath
  ? JSON.parse(await readFile(mapProofCorpusPath, "utf8"))
  : { vectors: [] };
if (
  mapProofCorpus.schema_version !== "malt.map-proof.conformance/v1" ||
  !Array.isArray(mapProofCorpus.vectors) ||
  mapProofCorpus.vectors.length === 0
) {
  throw new Error(`${mapProofCorpusPath} is not a non-empty Map-proof v1 corpus`);
}

globalThis.maltVerifierBackend = selectedBackend;
const go = new globalThis.Go();
const wasm = await readFile(wasmPath);
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
let runtimeFailure;
void go.run(instance).catch((error) => {
  runtimeFailure = error;
});

await waitForVerifierGlobals();
const invalidMapProof = JSON.parse(globalThis.maltVerifyMapProof("{}"));
if (invalidMapProof.valid !== false || invalidMapProof.profile !== "malt.map-proof/v0alpha1") {
  throw new Error("maltVerifyMapProof did not fail closed on an invalid verification envelope");
}

const allVectors = [...corpus.vectors, ...mapProofCorpus.vectors];
const vectors =
  selectedBackend === "all"
    ? allVectors
    : allVectors.filter(
        (vector) => vector.backend === selectedBackend || vector.backend === "none",
      );
if (
  selectedBackend !== "all" &&
  (!vectors.some((vector) => vector.operation === "map_proof" && vector.backend === selectedBackend) ||
    !vectors.some(
      (vector) =>
        (vector.operation === "resolve" || vector.operation === "read") &&
        vector.backend === selectedBackend,
    ))
) {
  throw new Error(`conformance corpora have no complete ${selectedBackend} backend selection`);
}
const seen = new Set();
const failures = [];
for (const vector of vectors) {
  const label = typeof vector.id === "string" ? vector.id : "<missing-id>";
  try {
    validateEnvelope(vector, seen);
    const verify = selectVerifier(vector.operation);
    const response = JSON.parse(verify(JSON.stringify(vector.verification)));
    if (typeof response.valid !== "boolean") {
      throw new Error("verifier response has no boolean valid field");
    }
    if (response.valid !== vector.expected.valid) {
      const diagnostic = response.error ? `: ${response.error}` : "";
      throw new Error(
        `expected valid=${vector.expected.valid}, got valid=${response.valid}${diagnostic}`,
      );
    }
  } catch (error) {
    failures.push(`${label}: ${error instanceof Error ? error.message : error}`);
  }
}

if (failures.length > 0) {
  console.error(`WASM ${selectedBackend} verification failed (${failures.length}/${vectors.length}):`);
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

const mapProofCount = vectors.filter((vector) => vector.operation === "map_proof").length;
console.log(
  `WASM ${selectedBackend} verification passed (${vectors.length - mapProofCount} Resolve/Read conformance vectors; ${mapProofCount} Map-proof conformance vectors)`,
);
process.exit(0);

function selectVerifier(operation) {
  switch (operation) {
    case "resolve":
      return globalThis.maltVerifyResolve;
    case "read":
      return globalThis.maltVerifyRead;
    case "map_proof":
      return globalThis.maltVerifyMapProof;
    default:
      throw new Error(`unsupported operation ${JSON.stringify(operation)}`);
  }
}

function validateEnvelope(vector, ids) {
  if (!vector || typeof vector !== "object" || Array.isArray(vector)) {
    throw new Error("vector is not an object");
  }
  if (typeof vector.id !== "string" || vector.id.length === 0) {
    throw new Error("vector has no non-empty id");
  }
  if (ids.has(vector.id)) {
    throw new Error("duplicate vector id");
  }
  ids.add(vector.id);
  if (!vector.verification || typeof vector.verification !== "object" || Array.isArray(vector.verification)) {
    throw new Error("verification is not an object");
  }
  if (!vector.expected || typeof vector.expected.valid !== "boolean") {
    throw new Error("expected.valid is not a boolean");
  }
}

async function waitForVerifierGlobals() {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (runtimeFailure) {
      throw new Error(`Go WASM runtime failed: ${runtimeFailure}`);
    }
    if (
      typeof globalThis.maltVerifyResolve === "function" &&
      typeof globalThis.maltVerifyRead === "function" &&
      typeof globalThis.maltVerifyMapProof === "function"
    ) {
      if (globalThis.maltVerifierInitError) {
        throw new Error(`MALT verifier initialization failed: ${globalThis.maltVerifierInitError}`);
      }
      if (globalThis.maltVerifierLoadedBackend !== selectedBackend) {
        throw new Error(
          `MALT verifier loaded backend ${JSON.stringify(globalThis.maltVerifierLoadedBackend)}, expected ${JSON.stringify(selectedBackend)}`,
        );
      }
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out waiting for MALT verifier globals");
}
