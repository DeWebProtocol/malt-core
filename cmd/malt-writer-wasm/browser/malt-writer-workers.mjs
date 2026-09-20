const BACKENDS = new Set(["kzg", "ipa"]);
const IPA_PROFILES = new Set(["direct", "compact", "fast"]);

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function requireTarget(backend, profile = "") {
  if (!BACKENDS.has(backend)) {
    throw new Error(`unsupported writer backend ${JSON.stringify(backend)}`);
  }
  if (backend === "kzg") {
    if (profile !== "") {
      throw new Error("KZG writer must not select an IPA committer profile");
    }
  } else if (!IPA_PROFILES.has(profile)) {
    throw new Error(`unsupported IPA committer profile ${JSON.stringify(profile)}`);
  }
  return Object.freeze({ backend, profile });
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  void promise.catch(() => {});
  return { promise, resolve, reject };
}

function onceSignal() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function abortFailure(signal) {
  return signal?.reason instanceof Error
    ? signal.reason
    : new Error("MALT writer initialization was aborted");
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortFailure(signal);
}

// WebAssembly compilation promises are not cancellable in current browser
// APIs. This race releases the caller immediately and prevents a late compile
// settlement from becoming unhandled; the engine may still finish that compile
// in the background. Worker creation remains strictly after this await.
function raceWithAbort(promise, signal) {
  const observed = Promise.resolve(promise);
  if (!signal) return observed;
  if (signal.aborted) {
    // The operation was already started by the caller, so keep observing a
    // possible late rejection even though this consumer is done with it.
    void observed.catch(() => {});
    return Promise.reject(abortFailure(signal));
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const onAbort = () => {
      if (settled) return;
      settled = true;
      reject(abortFailure(signal));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    observed.then(
      (value) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

async function compileModule(
  wasmURL,
  fetchFunction,
  signal,
  compileStreamingFunction,
  compileFunction,
) {
  throwIfAborted(signal);
  const response = await fetchFunction(wasmURL, { signal });
  throwIfAborted(signal);
  if (!response.ok) {
    throw new Error(`fetch ${wasmURL}: HTTP ${response.status}`);
  }
  if (typeof compileStreamingFunction === "function") {
    const fallback = response.clone();
    try {
      const module = await raceWithAbort(compileStreamingFunction(response), signal);
      throwIfAborted(signal);
      return module;
    } catch {
      throwIfAborted(signal);
      const bytes = await raceWithAbort(fallback.arrayBuffer(), signal);
      throwIfAborted(signal);
      const module = await raceWithAbort(compileFunction(bytes), signal);
      throwIfAborted(signal);
      return module;
    }
  }
  const bytes = await raceWithAbort(response.arrayBuffer(), signal);
  throwIfAborted(signal);
  const module = await raceWithAbort(compileFunction(bytes), signal);
  throwIfAborted(signal);
  return module;
}

function defaultWorkerFactory({ backend, profile, workerURL }) {
  const suffix = profile ? `${backend}-${profile}` : backend;
  return new Worker(workerURL, { type: "module", name: `malt-writer-${suffix}` });
}

function validateWorker(worker) {
  if (
    !worker ||
    typeof worker.postMessage !== "function" ||
    typeof worker.addEventListener !== "function" ||
    typeof worker.terminate !== "function"
  ) {
    throw new Error("workerFactory must return a Worker-compatible object");
  }
  return worker;
}

// MaltWriterWorker owns exactly one immutable backend/profile WASM instance.
// Callers must terminate it before selecting a different implementation.
export class MaltWriterWorker {
  #target;
  #state;
  #nextRequestID = 1;

  constructor({
    backend,
    profile = "",
    module,
    wasmExecURL,
    workerURL,
    workerFactory = defaultWorkerFactory,
  }) {
    this.#target = requireTarget(backend, profile);
    try {
      WebAssembly.Module.exports(module);
    } catch {
      throw new Error("module must be a compiled WebAssembly.Module");
    }
    if (typeof wasmExecURL !== "string" || wasmExecURL.length === 0) {
      throw new Error("wasmExecURL must be a non-empty string");
    }
    if (typeof workerFactory !== "function") {
      throw new Error("workerFactory must be a function");
    }

    const ready = deferred();
    const fatal = onceSignal();
    this.#state = {
      phase: "initializing",
      error: undefined,
      ready,
      fatal,
      pending: new Map(),
      worker: undefined,
    };
    this.ready = ready.promise;
    // Fatal failures resolve instead of reject so an idle controller can be
    // observed without creating an unhandled-rejection hazard. Explicit
    // termination is not a failure and intentionally leaves this pending.
    this.fatal = fatal.promise;
    try {
      const worker = validateWorker(workerFactory({ ...this.#target, workerURL }));
      this.#state.worker = worker;
      worker.addEventListener("message", (event) => this.#handleMessage(event.data));
      worker.addEventListener("error", (event) => {
        this.#fail(event?.error ?? event?.message ?? "Worker error");
      });
      worker.addEventListener("messageerror", () => {
        this.#fail("Worker message could not be deserialized");
      });
      worker.postMessage({
        type: "initialize",
        ...this.#target,
        module,
        wasmExecURL,
      });
    } catch (error) {
      this.#fail(error);
    }
  }

  get backend() {
    return this.#target.backend;
  }

  get profile() {
    return this.#target.profile;
  }

  #handleMessage(message) {
    if (!message || typeof message !== "object") {
      this.#fail("Worker returned a non-object message");
      return;
    }
    for (const field of ["backend", "profile"]) {
      if (!Object.hasOwn(message, field)) {
        this.#fail(`Worker message is missing ${field}`);
        return;
      }
      if (message[field] !== this.#target[field]) {
        this.#fail(
          `Worker ${field} ${JSON.stringify(message[field])}, expected ${JSON.stringify(this.#target[field])}`,
        );
        return;
      }
    }
    if (message.type === "ready") {
      if (this.#state.phase !== "initializing") {
        this.#fail(`Worker became ready from state ${this.#state.phase}`);
        return;
      }
      this.#state.phase = "ready";
      this.#state.ready.resolve(this.#target);
      return;
    }
    if (message.type === "failed") {
      this.#fail(message.error ?? "Worker failed");
      return;
    }
    if (message.type !== "response") {
      this.#fail(`Worker returned unsupported message ${JSON.stringify(message.type)}`);
      return;
    }

    const pending = this.#state.pending.get(message.id);
    if (!pending) {
      this.#fail(`Worker returned unknown request id ${JSON.stringify(message.id)}`);
      return;
    }
    this.#state.pending.delete(message.id);
    if (message.error !== undefined) {
      pending.reject(new Error(String(message.error)));
    } else {
      pending.resolve(message.result);
    }
  }

  #fail(error) {
    if (this.#state.phase === "failed" || this.#state.phase === "terminated") return;
    const failure = error instanceof Error ? error : new Error(errorMessage(error));
    this.#stop("failed", failure);
  }

  #stop(phase, failure) {
    if (this.#state.phase === "failed" || this.#state.phase === "terminated") return;
    this.#state.phase = phase;
    this.#state.error = failure;
    const worker = this.#state.worker;
    this.#state.worker = undefined;
    try {
      worker?.terminate();
    } catch {
      // Readiness and pending requests are rejected even if a custom adapter
      // fails while releasing its underlying Worker.
    }
    this.#state.ready.reject(failure);
    for (const pending of this.#state.pending.values()) pending.reject(failure);
    this.#state.pending.clear();
    if (phase === "failed") this.#state.fatal.resolve(failure);
  }

  #requireBackend(backend) {
    if (backend !== this.backend) {
      throw new Error(
        `loaded ${this.backend} writer cannot serve ${JSON.stringify(backend)}`,
      );
    }
  }

  status(backend = this.backend) {
    this.#requireBackend(backend);
    return Object.freeze({
      ...this.#target,
      state: this.#state.phase,
      ...(this.#state.error ? { error: this.#state.error.message } : {}),
    });
  }

  whenReady(backend = this.backend) {
    this.#requireBackend(backend);
    return this.#state.ready.promise;
  }

  async #request(backend, method, args) {
    this.#requireBackend(backend);
    await this.#state.ready.promise;
    if (this.#state.phase !== "ready") {
      throw this.#state.error ?? new Error(`${backend} writer is not ready`);
    }
    const id = this.#nextRequestID++;
    if (!Number.isSafeInteger(id)) {
      throw new Error("MALT writer request id space is exhausted");
    }
    return new Promise((resolve, reject) => {
      this.#state.pending.set(id, { resolve, reject });
      try {
        this.#state.worker.postMessage({
          type: "request",
          ...this.#target,
          id,
          method,
          args,
        });
      } catch (error) {
        this.#state.pending.delete(id);
        reject(error);
      }
    });
  }

  prepareAuthentication(backend, stateJSON) {
    return this.#request(backend, "prepareAuthentication", [stateJSON]);
  }
  updateAuthentication(backend, candidateJSON, stateJSON) {
    return this.#request(backend, "updateAuthentication", [candidateJSON, stateJSON]);
  }
  createAuthentication(backend, stateJSON) {
    return this.#request(backend, "createAuthentication", [stateJSON]);
  }
  importAuthentication(backend, candidateJSON) {
    return this.#request(backend, "importAuthentication", [candidateJSON]);
  }
  applyAuthentication(backend, handle, deltaJSON) {
    return this.#request(backend, "applyAuthentication", [handle, deltaJSON]);
  }
  exportAuthentication(backend, handle) {
    return this.#request(backend, "exportAuthentication", [handle]);
  }
  discardAuthentication(backend, handle) {
    return this.#request(backend, "discardAuthentication", [handle]);
  }
  closeAuthentication(backend) {
    return this.#request(backend, "closeAuthentication", []);
  }
  compute(backend, transactionID, updateViewJSON, semanticIntentJSON) {
    return this.#request(backend, "compute", [transactionID, updateViewJSON, semanticIntentJSON]);
  }
  bootstrap(backend) { return this.#request(backend, "bootstrap", []); }
  load(backend, updateViewJSON) { return this.#request(backend, "load", [updateViewJSON]); }
  prepare(backend, transactionID, semanticIntentJSON) {
    return this.#request(backend, "prepare", [transactionID, semanticIntentJSON]);
  }
  getPreparedResult(backend, transactionID) {
    return this.#request(backend, "getPreparedResult", [transactionID]);
  }
  validateReceipt(backend, writerResultJSON, materializationReceiptJSON) {
    return this.#request(backend, "validateReceipt", [writerResultJSON, materializationReceiptJSON]);
  }
  acceptReceipt(backend, transactionID, materializationReceiptJSON) {
    return this.#request(backend, "acceptReceipt", [transactionID, materializationReceiptJSON]);
  }
  discard(backend, transactionID) { return this.#request(backend, "discard", [transactionID]); }
  closeSession(backend) {
    return this.#request(backend, "closeSession", []).then(() => undefined);
  }

  terminateBackend(backend) {
    this.#requireBackend(backend);
    this.terminate();
  }

  terminateAll() { this.terminate(); }

  terminate() {
    this.#stop("terminated", new Error(`${this.backend} writer was terminated`));
  }
}

export async function createMaltWriterWorker({
  backend,
  profile = "",
  wasmURL,
  wasmExecURL = new URL("./wasm_exec.js", import.meta.url),
  workerURL = new URL("./malt-writer-worker.mjs", import.meta.url),
  module,
  fetch: fetchFunction = globalThis.fetch,
  compileStreaming: compileStreamingFunction =
    globalThis.WebAssembly?.compileStreaming?.bind(globalThis.WebAssembly),
  compile: compileFunction = globalThis.WebAssembly?.compile?.bind(globalThis.WebAssembly),
  workerFactory,
  signal,
} = {}) {
  requireTarget(backend, profile);
  throwIfAborted(signal);
  let compiledModule = module;
  if (compiledModule === undefined) {
    if (wasmURL === undefined) throw new Error("wasmURL is required");
    if (typeof fetchFunction !== "function") {
      throw new Error("fetch is unavailable and no compiled module was provided");
    }
    if (typeof compileFunction !== "function") {
      throw new Error("WebAssembly.compile is unavailable and no compiled module was provided");
    }
    compiledModule = await compileModule(
      wasmURL,
      fetchFunction,
      signal,
      compileStreamingFunction,
      compileFunction,
    );
  }
  throwIfAborted(signal);
  return new MaltWriterWorker({
    backend,
    profile,
    module: compiledModule,
    wasmExecURL: String(wasmExecURL),
    workerURL,
    ...(workerFactory ? { workerFactory } : {}),
  });
}
