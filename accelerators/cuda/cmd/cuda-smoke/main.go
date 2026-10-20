// cuda-smoke checks actual device proofs against the independent CPU backend.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/dewebprotocol/malt-core/accelerators/cuda"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
)

func main() {
	var cfg cuda.Config
	flag.StringVar(&cfg.ICICLEInclude, "icicle-include", "", "ICICLE v2.8.0 icicle/include directory")
	flag.StringVar(&cfg.NVRTCLibrary, "nvrtc", "", "absolute NVRTC DLL/SO (optional)")
	flag.IntVar(&cfg.Device, "device", 0, "CUDA device ordinal")
	flag.IntVar(&cfg.Batch, "batch", 8, "maximum device batch")
	flag.IntVar(&cfg.Streams, "streams", 4, "CUDA streams")
	flag.DurationVar(&cfg.BatchWait, "batch-wait", 10*time.Millisecond, "microbatch collection window")
	flag.Parse()
	computer, err := cuda.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer computer.Close()
	if err := smoke(computer); err != nil {
		log.Print(err)
		_ = computer.Close()
		os.Exit(1)
	}
	if err := computer.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("PASS: independent vectors, indices 0/1/127/4095, infinity, CPU proof equality, verification and root binding")
}

func smoke(computer *cuda.Computer) error {
	cpu, err := kzg.NewScheme()
	if err != nil {
		return err
	}
	gpu, err := kzg.NewSchemeWithOpeningComputer(computer)
	if err != nil {
		return err
	}
	var group sync.WaitGroup
	failures := make(chan error, 12)
	var checks []func() error
	for vector := 0; vector < 3; vector++ {
		cells := make([]commitment.Cell, kzg.MaxValues)
		if vector < 2 {
			for i := range cells {
				cells[i] = commitment.NewCell([]byte{byte(i), byte(i >> 8), byte(vector + 1)})
			}
		}
		root, err := cpu.Commit(cells)
		if err != nil {
			return err
		}
		opening, err := gpu.PrepareOpening(root, cells)
		if err != nil {
			return err
		}
		for _, index := range []uint64{0, 1, 127, 4095} {
			_, expected, err := cpu.Prove(root, cells, index)
			if err != nil {
				return err
			}
			checks = append(checks, func() error {
				value, proof, err := opening.Open(index)
				if err == nil && !bytes.Equal(proof, expected) {
					err = fmt.Errorf("proof differs from CPU at %d", index)
				}
				if err == nil {
					var ok bool
					ok, err = cpu.VerifyIndex(root, index, value, proof)
					if err == nil && !ok {
						err = fmt.Errorf("CPU verification failed at %d", index)
					}
				}
				return err
			})
		}
		if vector < 2 {
			wrong := commitment.CloneCells(cells)
			wrong[0] = commitment.NewCell([]byte("wrong root"))
			if _, _, err := gpu.Prove(root, wrong, 0); err == nil {
				return fmt.Errorf("wrong root accepted")
			}
		}
	}
	start := make(chan struct{})
	for _, check := range checks {
		group.Go(func() { <-start; failures <- check() })
	}
	close(start)
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			return err
		}
	}
	return nil
}
