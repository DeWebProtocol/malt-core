package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dewebprotocol/malt-core/conformance/internal/generate"
)

func main() {
	out := flag.String("out", "", "output path for current typed authentication vectors")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: generate -out FILE")
		os.Exit(2)
	}
	data, err := generate.GenerateAuthentication()
	if err == nil {
		err = os.WriteFile(*out, data, 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
