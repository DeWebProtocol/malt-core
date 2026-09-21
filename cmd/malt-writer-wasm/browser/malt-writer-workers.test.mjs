import assert from "node:assert/strict";
import test from "node:test";

import { createMaltWriterWorker, MaltWriterWorker } from "./malt-writer-workers.mjs";

const EMPTY_WASM_MODULE = new WebAssembly.Module(
  new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
);

class FakeWorker {
  constructor(backend, profile, throwOnInitialize = false) {
    this.backend = backend;
    this.profile = profile;
    this.throwOnInitialize = throwOnInitialize;
    this.listeners = new Map();
    this.requests = [];
    this.requestWaiters = [];
    this.terminationCount = 0;
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  postMessage(message) {
    if (message.type === "initialize") {
      if (this.throwOnInitialize) throw new Error("initialize postMessage failed");
      this.initialization = message;
      return;
    }
    const waiter = this.requestWaiters.shift();
    if (waiter) waiter(message);
    else this.requests.push(message);
  }

  terminate() { this.terminationCount += 1; }

  emit(type, event) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }

  ready() {
    this.emit("message", {
      data: { type: "ready", backend: this.backend, profile: this.profile },
    });
  }

  fail(error) { this.emit("error", { error, message: error.message }); }

  messageError() { this.emit("messageerror", {}); }

  runtimeFailed(error) {
    this.emit("message", {
      data: {
        type: "failed",
        backend: this.backend,
        profile: this.profile,
        error,
      },
    });
  }

  nextRequest() {
    const request = this.requests.shift();
    if (request) return Promise.resolve(request);
    return new Promise((resolve) => this.requestWaiters.push(resolve));
  }

  respond(request, { result, error } = {}) {
    this.emit("message", {
      data: {
        type: "response",
        backend: this.backend,
        profile: this.profile,
        id: request.id,
        ...(error === undefined ? { result } : { error }),
      },
    });
  }
}

function newHarness({ backend = "ipa", profile = "compact", throwOnInitialize = false } = {}) {
  let worker;
  const writer = new MaltWriterWorker({
    backend,
    profile: backend === "ipa" ? profile : "",
    module: EMPTY_WASM_MODULE,
    wasmExecURL: "https://example.test/wasm_exec.js",
    workerURL: new URL("https://example.test/malt-writer-worker.mjs"),
    workerFactory: (target) => {
      worker = new FakeWorker(target.backend, target.profile, throwOnInitialize);
      return worker;
    },
  });
  return { writer, worker };
}

function deferredPromise() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

test("one controller starts exactly one immutable backend/profile Worker", async () => {
  const { writer, worker } = newHarness();
  assert.deepEqual(
    { ...worker.initialization, module: undefined },
    {
      type: "initialize",
      backend: "ipa",
      profile: "compact",
      module: undefined,
      wasmExecURL: "https://example.test/wasm_exec.js",
    },
  );
  worker.ready();
  assert.deepEqual(await writer.ready, { backend: "ipa", profile: "compact" });
  assert.deepEqual(writer.status(), {
    backend: "ipa",
    profile: "compact",
    state: "ready",
  });
  assert.throws(() => writer.status("kzg"), /loaded ipa writer cannot serve/);
  writer.terminate();
  assert.equal(worker.terminationCount, 1);
});

test("request errors keep the selected Worker alive", async () => {
  const { writer, worker } = newHarness({ backend: "kzg" });
  worker.ready();
  await writer.ready;

  const bootstrap = writer.createAuthentication("kzg", new Uint8Array([1]));
  const bootstrapRequest = await worker.nextRequest();
  assert.equal(bootstrapRequest.method, "createAuthentication");
  worker.respond(bootstrapRequest, { result: '{"id":"1","root":"selected-root"}' });
  assert.equal(await bootstrap, '{"id":"1","root":"selected-root"}');

  const invalidLoad = writer.importAuthentication("kzg", new Uint8Array([1]));
  const invalidRequest = await worker.nextRequest();
  worker.respond(invalidRequest, { error: "invalid candidate" });
  await assert.rejects(invalidLoad, /invalid candidate/);
  assert.equal(writer.status().state, "ready");
  assert.equal(worker.terminationCount, 0);

  const close = writer.closeAuthentication("kzg");
  const closeRequest = await worker.nextRequest();
  assert.equal(closeRequest.method, "closeAuthentication");
  worker.respond(closeRequest, { result: "closed" });
  assert.equal(await close, "closed");

  writer.terminate();
  assert.equal(worker.terminationCount, 1);
});

test("initialization and fatal failures terminate and reject work", async () => {
  const failed = newHarness({ throwOnInitialize: true });
  await assert.rejects(failed.writer.ready, /initialize postMessage failed/);
  assert.equal(failed.writer.status().state, "failed");
  assert.equal(failed.worker.terminationCount, 1);

  const { writer, worker } = newHarness();
  worker.ready();
  await writer.ready;
  const pending = writer.importAuthentication("ipa", new Uint8Array([1]));
  await worker.nextRequest();
  worker.fail(new Error("runtime crashed"));
  await assert.rejects(pending, /runtime crashed/);
  assert.deepEqual(writer.status(), {
    backend: "ipa",
    profile: "compact",
    state: "failed",
    error: "runtime crashed",
  });
  assert.equal(worker.terminationCount, 1);
});

test("idle Worker error, messageerror, and failed messages resolve fatal once", async () => {
  const cases = [
    {
      expected: "idle Worker crashed",
      trigger: (worker) => worker.fail(new Error("idle Worker crashed")),
    },
    {
      expected: "Worker message could not be deserialized",
      trigger: (worker) => worker.messageError(),
    },
    {
      expected: "idle runtime failed",
      trigger: (worker) => worker.runtimeFailed("idle runtime failed"),
    },
  ];

  for (const { expected, trigger } of cases) {
    const { writer, worker } = newHarness();
    worker.ready();
    await writer.ready;

    // Trigger before attaching a consumer to cover the late-subscriber race.
    trigger(worker);
    const failure = await writer.fatal;
    assert.ok(failure instanceof Error);
    assert.equal(failure.message, expected);
    assert.deepEqual(writer.status(), {
      backend: "ipa",
      profile: "compact",
      state: "failed",
      error: expected,
    });
    assert.equal(worker.terminationCount, 1);
  }
});

test("explicit termination does not resolve fatal", async () => {
  const { writer, worker } = newHarness();
  worker.ready();
  await writer.ready;
  let fatalResolved = false;
  void writer.fatal.then(() => { fatalResolved = true; });

  writer.terminate();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(fatalResolved, false);
  assert.equal(writer.status().state, "terminated");
  assert.equal(worker.terminationCount, 1);
});

test("ready and failed messages require an explicit exact backend/profile target", async () => {
  for (const { message, error } of [
    {
      message: { type: "ready", backend: "ipa" },
      error: "Worker message is missing profile",
    },
    {
      message: { type: "failed", profile: "compact", error: "runtime failed" },
      error: "Worker message is missing backend",
    },
    {
      message: { type: "ready", backend: "ipa", profile: "fast" },
      error: 'Worker profile "fast", expected "compact"',
    },
  ]) {
    const { writer, worker } = newHarness();
    worker.emit("message", { data: message });
    await assert.rejects(writer.ready, (failure) => failure.message === error);
    assert.deepEqual(writer.status(), {
      backend: "ipa",
      profile: "compact",
      state: "failed",
      error,
    });
    assert.equal(worker.terminationCount, 1);
  }
});

test("response messages require an explicit exact backend/profile target", async () => {
  const { writer, worker } = newHarness();
  worker.ready();
  await writer.ready;
  const pending = writer.createAuthentication("ipa", new Uint8Array([1]));
  const request = await worker.nextRequest();
  assert.equal(request.backend, "ipa");
  assert.equal(request.profile, "compact");
  worker.emit("message", {
    data: { type: "response", backend: "ipa", id: request.id, result: "ignored" },
  });
  await assert.rejects(pending, /missing profile/);
  assert.equal(writer.status().state, "failed");
  assert.equal(worker.terminationCount, 1);
});

test("invalid backend/profile combinations fail before a Worker starts", () => {
  const options = {
    module: EMPTY_WASM_MODULE,
    wasmExecURL: "https://example.test/wasm_exec.js",
    workerURL: new URL("https://example.test/malt-writer-worker.mjs"),
  };
  assert.throws(() => new MaltWriterWorker({ ...options, backend: "ipa" }), /unsupported IPA/);
  assert.throws(
    () => new MaltWriterWorker({ ...options, backend: "kzg", profile: "fast" }),
    /must not select/,
  );
  assert.throws(() => new MaltWriterWorker({ ...options, backend: "other" }), /unsupported writer/);
});

test("abort signal cancels an in-flight WASM fetch before a Worker starts", async () => {
  const controller = new AbortController();
  let receivedSignal;
  let workerStarts = 0;
  const creating = createMaltWriterWorker({
    backend: "ipa",
    profile: "fast",
    wasmURL: "https://example.test/malt-writer-ipa-fast.wasm",
    wasmExecURL: "https://example.test/wasm_exec.js",
    signal: controller.signal,
    fetch: (_url, options) => {
      receivedSignal = options.signal;
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
      });
    },
    workerFactory: () => {
      workerStarts += 1;
      return new FakeWorker("ipa", "fast");
    },
  });

  controller.abort(new Error("profile selection changed"));
  await assert.rejects(creating, /profile selection changed/);
  assert.equal(receivedSignal, controller.signal);
  assert.equal(workerStarts, 0);
});

test("an already-aborted signal rejects a compiled module before Worker creation", async () => {
  const controller = new AbortController();
  controller.abort(new Error("component unmounted"));
  let workerStarts = 0;
  await assert.rejects(
    createMaltWriterWorker({
      backend: "kzg",
      module: EMPTY_WASM_MODULE,
      wasmExecURL: "https://example.test/wasm_exec.js",
      signal: controller.signal,
      workerFactory: () => {
        workerStarts += 1;
        return new FakeWorker("kzg", "");
      },
    }),
    /component unmounted/,
  );
  assert.equal(workerStarts, 0);
});

for (const compileMode of ["compileStreaming", "compile"]) {
  test(`abort rejects immediately during WebAssembly.${compileMode} without starting a Worker`, async () => {
    const controller = new AbortController();
    const compileStarted = deferredPromise();
    const compileFinished = deferredPromise();
    let workerStarts = 0;
    const compile = () => {
      compileStarted.resolve();
      return compileFinished.promise;
    };
    const response = {
      ok: true,
      clone() { return this; },
      async arrayBuffer() { return new ArrayBuffer(8); },
    };
    const creating = createMaltWriterWorker({
      backend: "ipa",
      profile: "direct",
      wasmURL: "https://example.test/malt-writer-ipa-direct.wasm",
      wasmExecURL: "https://example.test/wasm_exec.js",
      signal: controller.signal,
      fetch: async () => response,
      compileStreaming: compileMode === "compileStreaming" ? compile : null,
      compile: compileMode === "compile" ? compile : () => {
        throw new Error("fallback compile must not start");
      },
      workerFactory: () => {
        workerStarts += 1;
        return new FakeWorker("ipa", "direct");
      },
    });

    await compileStarted.promise;
    controller.abort(new Error("writer selection changed during compile"));
    const outcome = await Promise.race([
      creating.then(
        () => new Error("initialization unexpectedly resolved"),
        (error) => error,
      ),
      new Promise((resolve) => setImmediate(() => resolve("still pending"))),
    ]);
    assert.notEqual(outcome, "still pending");
    assert.match(outcome.message, /selection changed during compile/);
    assert.equal(workerStarts, 0);

    // A late engine rejection remains observed after the caller has already
    // received the abort failure.
    compileFinished.reject(new Error("late engine compile failure"));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(workerStarts, 0);
  });
}
