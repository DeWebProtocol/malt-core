package cuda

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeDevice struct {
	openFunc func([]job) ([][48]byte, error)
	closed   chan struct{}
}

func (d *fakeDevice) open(j []job) ([][48]byte, error) { return d.openFunc(j) }
func (d *fakeDevice) close() error                     { close(d.closed); return nil }

func TestBatchesPreserveIndependentWitnessesAndIndices(t *testing.T) {
	cfg, _ := normalize(Config{Batch: 4, BatchWait: 10 * time.Millisecond})
	d := &fakeDevice{closed: make(chan struct{})}
	d.openFunc = func(jobs []job) ([][48]byte, error) {
		p := make([][48]byte, len(jobs))
		for i, j := range jobs {
			p[i][0] = byte(j.index)
			p[i][1] = j.evaluations[j.index][31]
		}
		return p, nil
	}
	c, err := start(cfg, func() (device, error) { return d, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Go(func() {
			v := make([][32]byte, 4096)
			v[i][31] = byte(i + 10)
			p, err := c.Open(v, uint64(i))
			if err != nil || p[0] != byte(i) || p[1] != byte(i+10) {
				t.Errorf("independent result %d: %x %v", i, p, err)
			}
		})
	}
	group.Wait()
}

func TestDeviceFailureRejectsQueuedAndFutureWork(t *testing.T) {
	failure := errors.New("device lost")
	d := &fakeDevice{closed: make(chan struct{}), openFunc: func([]job) ([][48]byte, error) { return nil, failure }}
	cfg, _ := normalize(Config{})
	c, err := start(cfg, func() (device, error) { return d, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2; i++ {
		if _, err := c.Open(make([][32]byte, 4096), 0); !errors.Is(err, failure) {
			t.Fatalf("failure lost: %v", err)
		}
	}
}

func TestCloseWaitsForActiveDeviceBeforeFree(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	d := &fakeDevice{closed: make(chan struct{})}
	d.openFunc = func(j []job) ([][48]byte, error) { close(entered); <-release; return make([][48]byte, len(j)), nil }
	cfg, _ := normalize(Config{Batch: 1, MaxPending: 1})
	c, err := start(cfg, func() (device, error) { return d, nil })
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.Open(make([][32]byte, 4096), 0); result <- err }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller not released")
	}
	select {
	case <-d.closed:
		t.Fatal("device freed during active compute")
	default:
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(make([][32]byte, 4096), 0); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestCanonicalInputsAndConfiguration(t *testing.T) {
	for _, cfg := range []Config{{Batch: -1}, {Batch: 65}, {Streams: 9}, {MaxPending: -1}, {BatchWait: -1}} {
		if _, err := normalize(cfg); err == nil {
			t.Fatal("invalid config", cfg)
		}
	}
	var c Computer
	if _, err := c.Open(nil, 0); err == nil {
		t.Fatal("nil vector accepted")
	}
	v := make([][32]byte, 4096)
	v[0] = scalarModulus
	if _, err := c.Open(v, 0); err == nil {
		t.Fatal("noncanonical scalar accepted")
	}
}

func TestPendingLimitIncludesOnlyBoundedWaitingBuffer(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	d := &fakeDevice{closed: make(chan struct{}), openFunc: func(j []job) ([][48]byte, error) {
		once.Do(func() { close(entered) })
		<-release
		return make([][48]byte, len(j)), nil
	}}
	cfg, _ := normalize(Config{Batch: 1, MaxPending: 1})
	c, err := start(cfg, func() (device, error) { return d, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	results := make(chan error, 2)
	go func() { _, err := c.Open(make([][32]byte, 4096), 0); results <- err }()
	<-entered
	go func() { _, err := c.Open(make([][32]byte, 4096), 1); results <- err }()
	deadline := time.After(time.Second)
	for len(c.jobs) != 1 {
		select {
		case <-deadline:
			t.Fatal("pending job not queued")
		case <-time.After(time.Millisecond):
		}
	}
	if _, err := c.Open(make([][32]byte, 4096), 2); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPinnedSource(t *testing.T) {
	include := os.Getenv("MALT_CUDA_ICICLE_INCLUDE")
	if include == "" {
		t.Skip("set MALT_CUDA_ICICLE_INCLUDE to validate external pinned headers")
	}
	if _, err := mathSource(include); err != nil {
		t.Fatal(err)
	}
}

func TestDomainAndInfinityEncoding(t *testing.T) {
	roots, diff := domainBytes()
	if len(roots) != 4096*32 || len(diff) != len(roots) || roots[0] != 1 || diff[0] != 0 {
		t.Fatal("domain encoding")
	}
	p, err := encodePoint(make([]byte, 96))
	if err != nil || p[0] != 0xc0 {
		t.Fatal(p, err)
	}
	if _, err := encodePoint(make([]byte, 95)); err == nil {
		t.Fatal("short point accepted")
	}
}
