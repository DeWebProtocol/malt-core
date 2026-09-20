import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Worker as NodeWorker } from "node:worker_threads";
import { pathToFileURL } from "node:url";

const [wasmPath, wasmExecPath, controllerPath, workerPath, backend, profile = ""] =
  process.argv.slice(2);
if (!wasmPath || !wasmExecPath || !controllerPath || !workerPath || !backend) {
  console.error(
    "usage: node run-writer-worker-smoke.mjs <writer.wasm> <wasm_exec.js> <controller.mjs> <worker.mjs> <kzg|ipa> [direct|compact|fast]",
  );
  process.exit(2);
}

const [{ createMaltWriterWorker }, wasm] = await Promise.all([
  import(pathToFileURL(controllerPath).href),
  readFile(wasmPath),
]);
const module = await WebAssembly.compile(wasm);
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

  const bytes = value => new TextEncoder().encode(value);
  const json = value => bytes(JSON.stringify(value));
  const state = { descriptor: { layout: 1, input_rule: 1, vc_profile: backend === 'ipa' ? 2 : 1 }, entries: [] };
  const base = JSON.parse(await writer.createAuthentication(backend, json(state)));
  const next = JSON.parse(await writer.applyAuthentication(backend, bytes(base.handle), json({
    profile: 'malt.authentication-delta/0', changes: [{ input: { kind: 'label', data: 'ZmlsZQ==' }, after: 'bafkqaaa' }]
  })));
  assert.notEqual(next.root, base.root);
  const exported = JSON.parse(await writer.exportAuthentication(backend, bytes(next.handle)));
  const imported = JSON.parse(await writer.importAuthentication(backend, json(exported)));
  assert.equal(imported.root, next.root);
  const batch = { profile: 'malt.authentication-batch/0', transaction_id: 'worker-smoke', base: base.root, root: next.root, candidates: [exported] };
  const digest = await writer.validateAuthenticationBatch(backend, json(batch));
  const receipt = { profile: 'malt.authentication-receipt/0', transaction_id: batch.transaction_id, base: batch.base, root: batch.root, digest, durable_boundary: 'worker-smoke/0' };
  assert.equal(await writer.validateAuthenticationReceipt(backend, json(batch), json(receipt)), next.root);
  await assert.rejects(writer.validateAuthenticationReceipt(backend, json(batch), json({ ...receipt, root: base.root })));
  // Queued export completes before close invalidates every retained handle.
  const pendingExport = writer.exportAuthentication(backend, bytes(next.handle));
  const pendingClose = writer.closeAuthentication(backend);
  assert.equal(JSON.parse(await pendingExport).root, next.root);
  await pendingClose;
  await assert.rejects(writer.exportAuthentication(backend, bytes(next.handle)));

  console.log(
    `single Worker smoke passed; target ${backend}${profile ? `/${profile}` : ""}; ready ${(performance.now() - startedAt).toFixed(1)} ms; thread ${workerThreads[0].threadId}`,
  );
} finally {
  writer.terminate();
}
