package main

import (
	"flag"
	"fmt"
	"github.com/dewebprotocol/malt-core/internal/conformancegen"
	"os"
)

func main() {
	out := flag.String("out", "", "output path for current typed authentication vectors")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: conformancegen -out FILE")
		os.Exit(2)
	}
	data, err := conformancegen.GenerateAuthentication()
	if err == nil {
		err = os.WriteFile(*out, data, 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
