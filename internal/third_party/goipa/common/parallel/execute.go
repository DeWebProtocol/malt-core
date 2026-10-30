// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parallel

import (
	"runtime"
	"sync"
)

// Execute divides [0, nbIterations) into disjoint ranges. It uses the current
// GOMAXPROCS budget, optionally reduced by a positive maxCpus limit. Empty work
// is skipped and a single range runs directly on the caller.
func Execute(nbIterations int, work func(int, int), maxCpus ...int) {
	if nbIterations <= 0 {
		return
	}
	nbTasks := min(runtime.GOMAXPROCS(0), nbIterations)
	if len(maxCpus) == 1 && maxCpus[0] > 0 {
		nbTasks = min(nbTasks, maxCpus[0])
	}
	if nbTasks == 1 {
		work(0, nbIterations)
		return
	}

	var wg sync.WaitGroup
	wg.Add(nbTasks - 1)
	for i := 0; i < nbTasks; i++ {
		start := i * nbIterations / nbTasks
		end := (i + 1) * nbIterations / nbTasks
		if i == nbTasks-1 {
			work(start, end)
			break
		}
		go func() {
			defer wg.Done()
			work(start, end)
		}()
	}
	wg.Wait()
}
