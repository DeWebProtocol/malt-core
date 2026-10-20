# Optional Go/CUDA KZG opening computer

This independent Go module implements Core's `kzg.OpeningComputer`. Go calls
CUDA Driver and NVRTC through `purego`, on Linux/amd64 and Windows/amd64.
NVRTC compiles CUDA C++ kernels at initialization. **No Python, CuPy, CGO,
NVCC build or host C++ compiler is required.** Default Core, CPU verification
and browser/WASM builds do not import this module.

It accelerates the quotient and G1 MSM for the exact KZG4096 profile. Core
still hashes cells, constructs commitments, serializes proofs, and verifies
full `Prove` results against the caller-selected commitment. Prepared `Open`
consumers must verify each result before using or caching it, as with CPU.

The scheduling kernels use field/point arithmetic from ICICLE v2.8.0 (MIT), not ICICLE's MSM API. The external checkout is pinned to
`aacec3f72f14f53dd96d835698d2c87cde3a68b8`; every compiled header has a checked
SHA-256 in `worker/headers.json`. Headers must retain LF line endings.
This is an optional implementation pending hardware correctness/performance
qualification; historical evaluator GPU results do not validate this backend.

## Windows 11 / Git Bash

Install Go using this module's `go.mod` version. An NVIDIA driver and the CUDA
Toolkit's NVRTC library are required. If CUDA Toolkit 13.x is already installed
with NVRTC, it need not be reinstalled. Check `CUDA_PATH` points to the Toolkit;
its `bin` directory must also contain the matching NVRTC builtins DLL. A driver
version reported by `nvidia-smi` alone does not establish that NVRTC is installed.

Run from **this directory**, not the workspace root:

```bash
bash scripts/prepare-icicle.sh
bash scripts/cuda-smoke.sh
```

If automatic NVRTC discovery fails, pass its full path, for example:

```bash
bash scripts/cuda-smoke.sh --nvrtc 'C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.3/bin/nvrtc64_130_0.dll'
```

Smoke compares device proofs byte-for-byte with CPU and checks CPU verification,
different witnesses, indices 0/1/127/4095, all-zero/infinity behavior and wrong
root rejection. A smoke pass establishes correctness for those cases, not an
end-to-end latency SLO. Linux uses the same scripts; NVRTC discovery tries
`libnvrtc.so`, `.so.13`, `.so.12`, or the explicit `--nvrtc` path.

## Embedding

```go
computer, err := cuda.New(cuda.Config{ICICLEInclude: include, Batch: 8, Streams: 4})
if err != nil { return err }
defer computer.Close()
scheme, err := kzg.NewSchemeWithOpeningComputer(computer)
// Inject scheme as the exact KZG4096 commitment backend in the composing host.
```

One computer can serve concurrent schemes and scopes. It owns one private CUDA
context, resident fixed SRS table, multiple streams and reusable bounded buffers.
`BatchWait` is optional (zero by default); `MaxPending` bounds its local pending
buffer, in addition to its active batch. Service queue, deadlines, tenant quotas,
CPU/GPU routing and retries belong to the host. Device failure rejects work; it
never silently retries on CPU. `Close` releases pending callers and waits for
active device operations before freeing buffers. CUDA calls cannot be safely
interrupted by a Go context deadline.

The module requires an exact pushed Core API revision in `go.mod`. It does not
depend on Gateway or the evaluator. The composing executable owns CUDA lifetime:
stop requests, close the Gateway/runtime, then close the computer. CPU/GPU mixing
must be an explicit host policy and must preserve the same Core profile.

## Validation without a GPU

```bash
GOWORK=off go test ./...
GOWORK=off go vet ./...
CGO_ENABLED=0 GOWORK=off go build ./...
```

These run simulated-device scheduling/lifecycle tests and CPU encoding checks.
Set `MALT_CUDA_ICICLE_INCLUDE` to additionally check the pinned source assembly.
They do not execute a CUDA kernel; use the smoke command on an NVIDIA machine.
With both that variable and `MALT_CUDA_NVRTC_LIBRARY` pointing at an NVRTC
DLL/SO, `go test -run TestNVRTCCompilation` additionally compiles the real kernel
for `compute_86` through the Go FFI without requiring a GPU/driver.
