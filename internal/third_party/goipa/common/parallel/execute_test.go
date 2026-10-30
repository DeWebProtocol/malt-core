package parallel

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestExecuteHonorsCurrentBudgetAndCoversWork(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, budget := range []int{1, 2, 4, 1} {
		runtime.GOMAXPROCS(budget)
		for _, count := range []int{0, 1, 3, 17} {
			for _, limit := range []int{-1, 0, 1, 2, 8} {
				t.Run(fmt.Sprintf("budget%d/count%d/limit%d", budget, count, limit), func(t *testing.T) {
					hits := make([]atomic.Int32, count)
					var calls atomic.Int32
					work := func(start, end int) {
						calls.Add(1)
						if start < 0 || start >= end || end > count {
							t.Errorf("invalid range [%d, %d) for %d iterations", start, end, count)
							return
						}
						for i := start; i < end; i++ {
							hits[i].Add(1)
						}
					}
					if limit == -1 {
						Execute(count, work)
					} else {
						Execute(count, work, limit)
					}
					for i := range hits {
						if got := hits[i].Load(); got != 1 {
							t.Errorf("iteration %d ran %d times", i, got)
						}
					}
					maxTasks := min(budget, count)
					if limit > 0 {
						maxTasks = min(maxTasks, limit)
					}
					if got := int(calls.Load()); got != maxTasks {
						t.Errorf("work called %d times, want %d", got, maxTasks)
					}
				})
			}
		}
	}
}
