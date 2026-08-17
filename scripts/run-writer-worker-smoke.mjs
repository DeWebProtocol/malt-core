import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Worker as NodeWorker } from "node:worker_threads";
import { pathToFileURL } from "node:url";

const [wasmPath, wasmExecPath, controllerPath, workerPath, fixturePath, backend, profile = ""] =
  process.argv.slice(2);
if (!wasmPath || !wasmExecPath || !controllerPath || !workerPath || !fixturePath || !backend) {
  console.error(
    "usage: node run-writer-worker-smoke.mjs <writer.wasm> <wasm_exec.js> <controller.mjs> <worker.mjs> <client-root-vectors.json> <kzg|ipa> [direct|compact|fast]",
  );
  process.exit(2);
}

const [{ createMaltWriterWorker }, wasm, fixtureJSON] = await Promise.all([
  import(pathToFileURL(controllerPath).href),
  readFile(wasmPath),
  readFile(fixturePath, "utf8"),
]);
const module = await WebAssembly.compile(wasm);
const corpus = JSON.parse(fixtureJSON);
assert.equal(corpus.schema_version, "malt.client-root.conformance/v1");
assert.ok(Array.isArray(corpus.vectors), "client-root corpus has no vectors array");
const fixture = corpus.vectors.find(
  (candidate) => candidate.backend === backend && candidate.expected?.valid === true,
);
assert.ok(fixture, `missing ${backend} fixture`);
const nodeWorkerWrapper = new URL("./run-writer-worker-node.mjs", import.meta.url);
const workerThreads = [];

class NodeWorkerAdapter {
  constructor(workerURL) {
    this.worker = new NodeWorker(nodeWorkerWrapper, {
      workerData: { workerURL: String(workerURL) },
    });
    workerThreads.push(this.worker);
  }
  addEventListener(type, listener) {
    if (type === "message") {
      this.worker.on("message", (data) => listener({ data }));
    } else if (type === "error") {
      this.worker.on("error", (error) => listener({ error, message: error.message }));
    } else if (type === "messageerror") {
      this.worker.on("messageerror", (error) => listener({ error }));
    }
  }
  postMessage(message) { this.worker.postMessage(message); }
  terminate() { return this.worker.terminate(); }
}

const startedAt = performance.now();
const writer = await createMaltWriterWorker({
  backend,
  profile,
  module,
  wasmExecURL: pathToFileURL(wasmExecPath),
  workerURL: pathToFileURL(workerPath),
  workerFactory: ({ workerURL }) => new NodeWorkerAdapter(workerURL),
});

try {
  assert.equal(workerThreads.length, 1, "controller started more than one Worker");
  assert.equal(writer.status().state, "initializing");
  await writer.ready;
  assert.deepEqual(writer.status(), { backend, profile, state: "ready" });

  const encoder = new TextEncoder();
  const loadedRoot = await writer.load(
    backend,
    encoder.encode(JSON.stringify(fixture.update_view)),
  );
  assert.equal(loadedRoot, fixture.update_view.base_root);
  const candidate = await writer.prepare(
    backend,
    encoder.encode(fixture.operation_id),
    encoder.encode(JSON.stringify(fixture.semantic_intent)),
  );
  assert.equal(candidate, fixture.expected.bundle.candidate);
  const preparedJSON = await writer.getPreparedResult(
    backend,
    encoder.encode(fixture.operation_id),
  );
  const prepared = JSON.parse(preparedJSON);
  assert.deepStrictEqual(prepared.bundle, fixture.expected.bundle);
  assert.deepStrictEqual(prepared.materialization, fixture.expected.materialization);
  assert.deepStrictEqual(prepared.next_view, fixture.expected.next_view);

  const orderedReload = writer.load(
    backend,
    encoder.encode(JSON.stringify(fixture.update_view)),
  );
  const orderedClose = writer.closeSession(backend);
  assert.equal(await orderedReload, fixture.update_view.base_root);
  assert.equal(await orderedClose, undefined);
  await assert.rejects(
    writer.prepare(
      backend,
      encoder.encode(`${fixture.operation_id}-after-close`),
      encoder.encode(JSON.stringify(fixture.semantic_intent)),
    ),
    /has no update view/,
  );

  console.log(
    `single Worker smoke passed; target ${backend}${profile ? `/${profile}` : ""}; ready ${(performance.now() - startedAt).toFixed(1)} ms; thread ${workerThreads[0].threadId}`,
  );
} finally {
  writer.terminate();
}
