//go:build amd64 && (linux || windows)

package cuda

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

const bucketCount = 16 * 64 * 15

type shard struct {
	stream                                 uintptr
	vector, q, contributions, indices, out uint64
	scratch                                []uint64
	host, hostInput, hostIndices           unsafe.Pointer // Driver-owned pinned storage.
}

type cudaDevice struct {
	d                         *driver
	ctx, module               uintptr
	functions                 map[string]uintptr
	table, roots, differences uint64
	shards                    []shard
	levels                    []int
}

func newDevice(cfg Config, source string, parameters []byte) (result device, err error) {
	d, err := loadDriver(cfg.NVRTCLibrary)
	if err != nil {
		return nil, err
	}
	c := &cudaDevice{d: d, functions: map[string]uintptr{}}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	if err = check(d.init(0), "cuInit"); err != nil {
		return nil, err
	}
	var dev, major, minor int32
	if err = check(d.deviceGet(&dev, int32(cfg.Device)), "cuDeviceGet"); err != nil {
		return nil, err
	}
	if err = check(d.attribute(&major, 75, dev), "compute capability major"); err != nil {
		return nil, err
	}
	if err = check(d.attribute(&minor, 76, dev), "compute capability minor"); err != nil {
		return nil, err
	}
	ptx, err := d.compile(source, major, minor)
	if err != nil {
		return nil, err
	}
	if err = check(d.create(&c.ctx, 0, dev), "cuCtxCreate_v2"); err != nil {
		return nil, err
	}
	if err = check(d.load(&c.module, &ptx[0]), "cuModuleLoadData"); err != nil {
		return nil, err
	}
	for _, name := range []string{"precompute", "quotient", "quotient_diagonal", "buckets", "reduce", "normalize"} {
		var fn uintptr
		if err = check(d.function(&fn, c.module, "kzg_"+name), "cuModuleGetFunction"); err != nil {
			return nil, err
		}
		c.functions[name] = fn
	}
	if len(parameters) != 4096*96 {
		return nil, errors.New("invalid KZG setup length")
	}
	bases := make([]byte, len(parameters))
	for i := 0; i < len(parameters); i += 48 {
		reverse(bases[i:i+48], parameters[i:i+48])
	}
	baseptr, err := c.upload(bases)
	if err != nil {
		return nil, err
	}
	if err = c.allocate(&c.table, 64*4096*144); err != nil {
		return nil, err
	}
	if err = d.kernel(c.functions["precompute"], 32, 1, 128, 0, baseptr, c.table, 4096, 4, 64); err != nil {
		return nil, err
	}
	if err = check(d.sync(), "precompute synchronize"); err != nil {
		return nil, err
	}
	if err = check(d.free(baseptr), "release SRS upload"); err != nil {
		return nil, err
	}
	roots, differences := domainBytes()
	if c.roots, err = c.upload(roots); err != nil {
		return nil, err
	}
	if c.differences, err = c.upload(differences); err != nil {
		return nil, err
	}
	c.levels = []int{bucketCount}
	for c.levels[len(c.levels)-1] > 1 {
		n := c.levels[len(c.levels)-1]
		c.levels = append(c.levels, (n+127)/128)
	}
	perStream := (cfg.Batch + cfg.Streams - 1) / cfg.Streams
	perJob := 3*4096*32 + 4 + 96
	for _, n := range c.levels {
		perJob += n * 144
	}
	estimate := uintptr(perStream * cfg.Streams * perJob)
	var free, total uintptr
	if err = check(d.memory(&free, &total), "cuMemGetInfo"); err != nil {
		return nil, err
	}
	if estimate > free*7/10 {
		return nil, fmt.Errorf("CUDA workspace needs %d bytes; free %d (70%% budget)", estimate, free)
	}
	for i := 0; i < cfg.Streams; i++ {
		c.shards = append(c.shards, shard{})
		s := &c.shards[i]
		if err = check(d.streamCreate(&s.stream, 1), "cuStreamCreate"); err != nil {
			return nil, err
		}
		for _, allocation := range []struct {
			dst  *uint64
			size int
		}{{&s.vector, perStream * 4096 * 32}, {&s.q, perStream * 4096 * 32}, {&s.contributions, perStream * 4096 * 32}, {&s.indices, perStream * 4}, {&s.out, perStream * 96}} {
			if err = c.allocate(allocation.dst, allocation.size); err != nil {
				return nil, err
			}
		}
		s.scratch = make([]uint64, len(c.levels))
		for j, n := range c.levels {
			if err = c.allocate(&s.scratch[j], perStream*n*144); err != nil {
				return nil, err
			}
		}
		for _, allocation := range []struct {
			dst  *unsafe.Pointer
			size int
		}{{&s.host, perStream * 96}, {&s.hostInput, perStream * 4096 * 32}, {&s.hostIndices, perStream * 4}} {
			if err = check(d.hostAlloc(allocation.dst, uintptr(allocation.size), 0), "cuMemHostAlloc"); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

func (c *cudaDevice) allocate(dst *uint64, size int) error {
	return check(c.d.alloc(dst, uintptr(size)), "cuMemAlloc")
}
func (c *cudaDevice) upload(raw []byte) (uint64, error) {
	var p uint64
	if err := c.allocate(&p, len(raw)); err != nil {
		return 0, err
	}
	if err := check(c.d.toDevice(p, &raw[0], uintptr(len(raw))), "cuMemcpyHtoD"); err != nil {
		return p, err
	}
	// Pageable HtoD may return before DMA completes. Initialization must finish
	// these default-stream uploads before later nonblocking stream work.
	return p, check(c.d.streamSync(0), "initialization upload synchronize")
}

func (c *cudaDevice) open(batch []job) (points [][48]byte, err error) {
	// If any launch/copy fails, close synchronizes before reclaiming buffers.
	for k := 0; k < len(c.shards) && k < len(batch); k++ {
		s := &c.shards[k]
		var selection []int
		for j := k; j < len(batch); j += len(c.shards) {
			selection = append(selection, j)
		}
		b := len(selection)
		values := unsafe.Slice((*byte)(s.hostInput), b*4096*32)
		indices := unsafe.Slice((*byte)(s.hostIndices), b*4)
		for offset, j := range selection {
			for v := range batch[j].evaluations {
				start := (offset*4096 + v) * 32
				reverse(values[start:start+32], batch[j].evaluations[v][:])
			}
			binary.LittleEndian.PutUint32(indices[offset*4:], uint32(batch[j].index))
		}
		if err = check(c.d.toDeviceAsync(s.vector, s.hostInput, uintptr(len(values)), s.stream), "upload evaluations"); err != nil {
			return nil, err
		}
		if err = check(c.d.toDeviceAsync(s.indices, s.hostIndices, uintptr(len(indices)), s.stream), "upload indices"); err != nil {
			return nil, err
		}
		launch := func(name string, gx, gy, threads int, args ...uint64) error {
			return c.d.kernel(c.functions[name], gx, gy, threads, s.stream, args...)
		}
		if err = launch("quotient", (b*4096+127)/128, 1, 128, s.vector, c.roots, c.differences, s.indices, s.q, s.contributions, uint64(b)); err != nil {
			return nil, err
		}
		if err = launch("quotient_diagonal", b, 1, 256, s.q, s.contributions, s.indices); err != nil {
			return nil, err
		}
		if err = launch("buckets", (b*bucketCount+127)/128, 1, 128, c.table, s.q, s.scratch[0], 4096, 256, 4, 64, uint64(b)); err != nil {
			return nil, err
		}
		for i, n := range c.levels[:len(c.levels)-1] {
			if err = launch("reduce", (n+127)/128, b, 128, s.scratch[i], s.scratch[i+1], uint64(n)); err != nil {
				return nil, err
			}
		}
		if err = launch("normalize", (b+127)/128, 1, 128, s.scratch[len(s.scratch)-1], s.out, uint64(b)); err != nil {
			return nil, err
		}
		if err = check(c.d.toHostAsync(s.host, s.out, uintptr(b*96), s.stream), "cuMemcpyDtoHAsync"); err != nil {
			return nil, err
		}
	}
	points = make([][48]byte, len(batch))
	for k := 0; k < len(c.shards) && k < len(batch); k++ {
		s := &c.shards[k]
		if err = check(c.d.streamSync(s.stream), "cuStreamSynchronize"); err != nil {
			return nil, err
		}
		b := (len(batch) - k + len(c.shards) - 1) / len(c.shards)
		host := unsafe.Slice((*byte)(s.host), b*96)
		for offset, j := 0, k; j < len(batch); offset, j = offset+1, j+len(c.shards) {
			if points[j], err = encodePoint(host[offset*96 : (offset+1)*96]); err != nil {
				return nil, err
			}
		}
	}
	return points, nil
}

func (c *cudaDevice) close() error {
	var errs []error
	if c.ctx != 0 {
		errs = append(errs, check(c.d.sync(), "close synchronize"))
		for _, s := range c.shards {
			if s.stream != 0 {
				errs = append(errs, check(c.d.streamDestroy(s.stream), "cuStreamDestroy"))
			}
			for _, host := range []unsafe.Pointer{s.host, s.hostInput, s.hostIndices} {
				if host != nil {
					errs = append(errs, check(c.d.hostFree(host), "cuMemFreeHost"))
				}
			}
		}
		if c.module != 0 {
			errs = append(errs, check(c.d.unload(c.module), "cuModuleUnload"))
		}
		errs = append(errs, check(c.d.destroy(c.ctx), "cuCtxDestroy"))
	}
	errs = append(errs, c.d.close())
	return errors.Join(errs...)
}
