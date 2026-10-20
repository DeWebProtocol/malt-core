//go:build amd64 && (linux || windows)

package cuda

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// Model stream ordering, rather than CUDA timing: every kernel must follow
// both input uploads on its own stream. Host buffers stay alive through sync.
func TestShardInputsAndKernelsShareStream(t *testing.T) {
	d := &driver{}
	uploads := map[uintptr]int{}
	kernels := map[uintptr]int{}
	syncs := map[uintptr]bool{}
	d.toDeviceAsync = func(dst uint64, src unsafe.Pointer, n, stream uintptr) int32 {
		if stream != 7 && stream != 8 {
			t.Errorf("upload on unexpected stream %d", stream)
		}
		data := unsafe.Slice((*byte)(src), n)
		if dst == 10 || dst == 20 {
			want := byte(11)
			if stream == 8 {
				want = 22
			}
			if data[0] != want {
				t.Errorf("witness on stream %d: %d", stream, data[0])
			}
		}
		if dst == 13 || dst == 23 {
			want := uint32(0)
			if stream == 8 {
				want = 127
			}
			if binary.LittleEndian.Uint32(data) != want {
				t.Errorf("index on stream %d", stream)
			}
		}
		uploads[stream]++
		return 0
	}
	d.launch = func(_ uintptr, _, _, _, _, _, _, _ uint32, stream uintptr, _ *unsafe.Pointer, _ unsafe.Pointer) int32 {
		if uploads[stream] != 2 {
			t.Errorf("kernel ran before its uploads on stream %d", stream)
		}
		kernels[stream]++
		return 0
	}
	d.toHostAsync = func(_ unsafe.Pointer, _ uint64, _ uintptr, stream uintptr) int32 {
		if kernels[stream] != 4 {
			t.Errorf("output before kernels on stream %d", stream)
		}
		return 0
	}
	d.streamSync = func(stream uintptr) int32 { syncs[stream] = true; return 0 }
	c := &cudaDevice{d: d, functions: map[string]uintptr{}, levels: []int{1}}
	for i := 0; i < 2; i++ {
		input := make([]byte, 4096*32)
		indices := make([]byte, 4)
		out := make([]byte, 96)
		base := uint64(10 + i*10)
		c.shards = append(c.shards, shard{stream: uintptr(7 + i), vector: base, indices: base + 3, scratch: []uint64{100}, hostInput: unsafe.Pointer(&input[0]), hostIndices: unsafe.Pointer(&indices[0]), host: unsafe.Pointer(&out[0])})
	}
	jobs := []job{{evaluations: make([][32]byte, 4096), index: 0}, {evaluations: make([][32]byte, 4096), index: 127}}
	jobs[0].evaluations[0][31] = 11
	jobs[1].evaluations[0][31] = 22
	points, err := c.open(jobs)
	if err != nil || len(points) != 2 || points[0][0] != 0xc0 || points[1][0] != 0xc0 || !syncs[7] || !syncs[8] {
		t.Fatal(points, err, syncs)
	}
}
