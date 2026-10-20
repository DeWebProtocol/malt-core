// Package cuda implements an optional Go-controlled CUDA opening computer.
// CUDA Driver and NVRTC libraries are loaded by New; Python and CGO are not used.
package cuda

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
)

var ErrClosed = errors.New("CUDA opening computer is closed")
var ErrBusy = errors.New("CUDA opening computer pending limit exceeded")

// Config controls device computation. Service admission belongs to the host.
type Config struct {
	ICICLEInclude string // Pinned ICICLE v2.8.0 icicle/include directory.
	NVRTCLibrary  string // Optional absolute NVRTC DLL/SO path.
	Device        int
	Batch         int           // Default 8; maximum 64.
	Streams       int           // Default min(4, Batch).
	MaxPending    int           // Default 64, in addition to the active device batch.
	BatchWait     time.Duration // Optional microbatch collection window; default 0.
}

type result struct {
	point [48]byte
	err   error
}
type job struct {
	evaluations [][32]byte
	index       uint64
	result      chan result
}
type device interface {
	open([]job) ([][48]byte, error)
	close() error
}

// Computer submits batches on one locked OS thread, retaining a device context,
// fixed SRS table and bounded workspace. Its owner must call Close.
type Computer struct {
	cfg           Config
	jobs          chan job
	done, stopped chan struct{}
	once          sync.Once
	mu            sync.Mutex
	err, closeErr error
}

func normalize(cfg Config) (Config, error) {
	if cfg.Batch == 0 {
		cfg.Batch = 8
	}
	if cfg.Streams == 0 {
		cfg.Streams = min(4, cfg.Batch)
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 64
	}
	if cfg.Device < 0 || cfg.Batch < 1 || cfg.Batch > 64 || cfg.Streams < 1 || cfg.Streams > cfg.Batch || cfg.MaxPending < 1 || cfg.BatchWait < 0 || cfg.BatchWait > time.Second {
		return cfg, errors.New("invalid CUDA opening configuration")
	}
	return cfg, nil
}

// New compiles the pinned kernel with NVRTC and initializes the device.
// No installation or download occurs. Initialization can take several seconds.
func New(cfg Config) (*Computer, error) {
	var err error
	cfg, err = normalize(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.ICICLEInclude == "" {
		return nil, errors.New("ICICLE include directory is required")
	}
	source, err := mathSource(cfg.ICICLEInclude)
	if err != nil {
		return nil, err
	}
	parameters, err := kzg.OpeningParameters()
	if err != nil {
		return nil, err
	}
	return start(cfg, func() (device, error) { return newDevice(cfg, source, parameters) })
}

func start(cfg Config, factory func() (device, error)) (*Computer, error) {
	c := &Computer{cfg: cfg, jobs: make(chan job, cfg.MaxPending), done: make(chan struct{}), stopped: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(c.stopped)
		d, err := factory()
		ready <- err
		if err != nil {
			return
		}
		defer func() { c.closeErr = d.close() }()
		c.run(d)
	}()
	if err := <-ready; err != nil {
		<-c.stopped
		return nil, err
	}
	return c, nil
}

// Open waits for device completion. A full pending buffer returns ErrBusy.
// Device errors fail closed; there is no implicit CPU retry.
func (c *Computer) Open(evaluations [][32]byte, index uint64) ([48]byte, error) {
	if len(evaluations) != kzg.MaxValues || index >= kzg.MaxValues {
		return [48]byte{}, errors.New("invalid CUDA KZG vector or index")
	}
	for _, v := range evaluations {
		if bytes.Compare(v[:], scalarModulus[:]) >= 0 {
			return [48]byte{}, errors.New("noncanonical CUDA scalar")
		}
	}
	j := job{evaluations: append([][32]byte(nil), evaluations...), index: index, result: make(chan result, 1)}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return [48]byte{}, err
	}
	select {
	case c.jobs <- j:
		c.mu.Unlock()
	default:
		c.mu.Unlock()
		return [48]byte{}, ErrBusy
	}
	select {
	case r := <-j.result:
		return r.point, r.err
	case <-c.done:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		return [48]byte{}, err
	}
}

func (c *Computer) run(d device) {
	for {
		var first job
		select {
		case <-c.done:
			return
		case first = <-c.jobs:
		}
		batch := []job{first}
		if c.cfg.BatchWait > 0 && c.cfg.Batch > 1 {
			timer := time.NewTimer(c.cfg.BatchWait)
		collect:
			for len(batch) < c.cfg.Batch {
				select {
				case j := <-c.jobs:
					batch = append(batch, j)
				case <-timer.C:
					break collect
				case <-c.done:
					timer.Stop()
					return
				}
			}
			timer.Stop()
		}
	fill:
		for len(batch) < c.cfg.Batch {
			select {
			case j := <-c.jobs:
				batch = append(batch, j)
			default:
				break fill
			}
		}
		select {
		case <-c.done:
			return
		default:
		}
		points, err := d.open(batch)
		if err == nil && len(points) != len(batch) {
			err = errors.New("invalid CUDA completion count")
		}
		if err != nil {
			c.stop(fmt.Errorf("CUDA opening: %w", err))
			return
		}
		for i, j := range batch {
			j.result <- result{point: points[i]}
		}
	}
}

func (c *Computer) stop(err error) {
	c.once.Do(func() { c.mu.Lock(); c.err = err; close(c.done); c.mu.Unlock() })
}

// Close rejects new work, releases pending callers, and waits for in-flight
// CUDA work before freeing its context. Driver calls cannot be safely aborted
// by a Go deadline. Deadline and queue policy belong in the host executor.
func (c *Computer) Close() error {
	if c == nil {
		return nil
	}
	c.stop(ErrClosed)
	<-c.stopped
	return c.closeErr
}

var _ kzg.OpeningComputer = (*Computer)(nil)
