const SUPPORTED_BACKENDS = new Set(["kzg", "ipa"]);
const IPA_PROFILES = new Set(["direct", "compact", "fast"]);
const RPC_FUNCTIONS = Object.freeze({
  closeAuthentication: "maltCloseAuthentication",
  discardAuthentication: "maltDiscardAuthentication",
  exportAuthentication: "maltExportAuthentication",
  applyAuthentication: "maltApplyAuthentication",
  importAuthentication: "maltImportAuthentication",
  createAuthentication: "maltCreateAuthentication",
  updateAuthentication: "maltUpdateAuthentication",
  prepareAuthentication: "maltPrepareAuthentication",
  compute: "maltComputeClientRootV1",
  bootstrap: "maltWriterBootstrapSessionV1",
  load: "maltWriterLoadSessionV1",
  prepare: "maltWriterPrepareSessionV1",
  getPreparedResult: "maltWriterGetPreparedResultV1",
  validateReceipt: "maltWriterValidateReceiptV1",
  acceptReceipt: "maltWriterAcceptSessionReceiptV1",
  discard: "maltWriterDiscardSessionCandidateV1",
  closeSession: "maltWriterCloseSessionV1",
});
const STATEFUL_RPC_METHODS = new Set([
  "createAuthentication",
  "importAuthentication",
  "applyAuthentication",
  "exportAuthentication",
  "discardAuthentication",
  "closeAuthentication",
  "bootstrap",
  "load",
  "prepare",
  "getPreparedResult",
  "acceptReceipt",
  "discard",
  "closeSession",
]);

let initialized = false;
let ready = false;
let loadedBackend;
let loadedProfile = "";
let sessionRequestQueue = Promise.resolve();

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function postFailure(backend, error) {
  self.postMessage({
    type: "failed",
    backend,
    profile: loadedProfile,
    error: errorMessage(error),
  });
}

function requireTarget(backend, profile) {
  if (!SUPPORTED_BACKENDS.has(backend)) {
    throw new Error(`unsupported writer backend ${JSON.stringify(backend)}`);
  }
  if (backend === "kzg" && profile !== "") {
    throw new Error("KZG writer must not select an IPA committer profile");
  }
  if (backend === "ipa" && !IPA_PROFILES.has(profile)) {
    throw new Error(`unsupported IPA committer profile ${JSON.stringify(profile)}`);
  }
}

function requireMessageTarget(message) {
  for (const field of ["backend", "profile"]) {
    if (!Object.hasOwn(message, field)) {
      throw new Error(`Worker message is missing ${field}`);
    }
  }
  if (message.backend !== loadedBackend || message.profile !== loadedProfile) {
    throw new Error(
      `Worker message targets ${JSON.stringify(message.backend)}/${JSON.stringify(message.profile)}, ` +
        `loaded ${JSON.stringify(loadedBackend)}/${JSON.stringify(loadedProfile)}`,
    );
  }
}

async function initialize(message) {
  if (initialized) {
    throw new Error("MALT writer Worker is already initialized");
  }
  initialized = true;

  for (const field of ["backend", "profile"]) {
    if (!Object.hasOwn(message, field)) {
      throw new Error(`Worker initialize message is missing ${field}`);
    }
  }
  const { backend, profile, module, wasmExecURL } = message;
  requireTarget(backend, profile);
  if (typeof wasmExecURL !== "string" || wasmExecURL.length === 0) {
    throw new Error("wasmExecURL must be a non-empty string");
  }
  try {
    WebAssembly.Module.exports(module);
  } catch {
    throw new Error("module must be a compiled WebAssembly.Module");
  }

  loadedBackend = backend;
  loadedProfile = profile;
  await import(wasmExecURL);
  if (typeof globalThis.Go !== "function") {
    throw new Error(`${wasmExecURL} did not install the Go WASM runtime`);
  }

  const go = new globalThis.Go();
  go.argv = ["malt-writer.wasm", `--backend=${backend}`];
  const instance = await WebAssembly.instantiate(module, go.importObject);
  let runtimeFailure;
  void go.run(instance).catch((error) => {
    runtimeFailure = error;
    ready = false;
    postFailure(backend, new Error(`Go WASM runtime failed: ${errorMessage(error)}`));
  });

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (runtimeFailure) {
      throw runtimeFailure;
    }
    if (globalThis.maltWriterReady) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (!globalThis.maltWriterReady) {
    throw new Error("timed out waiting for the MALT writer runtime");
  }
  if (globalThis.maltWriterInitError) {
    throw new Error(`MALT writer initialization failed: ${globalThis.maltWriterInitError}`);
  }
  if (globalThis.maltWriterLoadedBackend !== backend) {
    throw new Error(
      `MALT writer loaded backend ${JSON.stringify(globalThis.maltWriterLoadedBackend)}, expected ${JSON.stringify(backend)}`,
    );
  }
  if (globalThis.maltWriterLoadedProfile !== profile) {
    throw new Error(
      `MALT writer loaded profile ${JSON.stringify(globalThis.maltWriterLoadedProfile)}, expected ${JSON.stringify(profile)}`,
    );
  }
  for (const functionName of Object.values(RPC_FUNCTIONS)) {
    if (typeof globalThis[functionName] !== "function") {
      throw new Error(`MALT writer did not register ${functionName}`);
    }
  }

  ready = true;
  self.postMessage({ type: "ready", backend, profile });
}

async function handleRequest(message) {
  const { id, method, args } = message;
  requireMessageTarget(message);
  if (!ready) {
    throw new Error(`${loadedBackend ?? "uninitialized"} writer is not ready`);
  }
  if (!Number.isSafeInteger(id) || id < 1) {
    throw new Error("request id must be a positive safe integer");
  }
  const functionName = RPC_FUNCTIONS[method];
  if (!functionName) {
    throw new Error(`unsupported writer method ${JSON.stringify(method)}`);
  }
  if (!Array.isArray(args)) {
    throw new Error("request args must be an array");
  }
  return globalThis[functionName](...args);
}

function postResponse(message, task) {
  void task.then(
    (result) => {
      self.postMessage({
        type: "response",
        backend: loadedBackend,
        profile: loadedProfile,
        id: message.id,
        result,
      });
    },
    (error) => {
      self.postMessage({
        type: "response",
        backend: loadedBackend,
        profile: loadedProfile,
        id: message.id,
        error: errorMessage(error),
      });
    },
  );
}

self.addEventListener("message", (event) => {
  const message = event.data;
  if (!message || typeof message !== "object") {
    postFailure(loadedBackend, new Error("Worker message must be an object"));
    return;
  }
  if (message.type === "initialize") {
    void initialize(message).catch((error) => {
      ready = false;
      postFailure(message.backend, error);
    });
    return;
  }
  if (message.type !== "request") {
    postFailure(loadedBackend, new Error(`unsupported Worker message ${JSON.stringify(message.type)}`));
    return;
  }

  if (STATEFUL_RPC_METHODS.has(message.method)) {
    const task = sessionRequestQueue.then(() => handleRequest(message));
    sessionRequestQueue = task.then(
      () => undefined,
      () => undefined,
    );
    postResponse(message, task);
    return;
  }
  postResponse(message, handleRequest(message));
});
