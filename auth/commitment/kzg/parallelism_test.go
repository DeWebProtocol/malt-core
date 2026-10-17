package kzg

import (
	"runtime"
	"testing"
)

func TestMSMConfigFollowsSchedulerBudget(t *testing.T) {
	previous := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	// Revisit a smaller budget to catch a task count cached at initialization.
	for _, budget := range []int{1, 2, 6, 1} {
		runtime.GOMAXPROCS(budget)
		if got := msmConfig().NbTasks; got != budget {
			t.Fatalf("GOMAXPROCS=%d: MSM task budget = %d, want %d", budget, got, budget)
		}
	}
}

func TestMSMConfigRespectsGnarkLimit(t *testing.T) {
	previous := runtime.GOMAXPROCS(1025)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	// gnark rejects explicit task counts above 1024. A larger scheduler budget
	// must not make otherwise valid commitments fail.
	if got := msmConfig().NbTasks; got < 1 || got > 1024 {
		t.Fatalf("MSM task budget = %d, outside gnark's supported range", got)
	}
}
