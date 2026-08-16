package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dewebprotocol/malt-core/internal/conformancegen"
)

func main() {
	out := flag.String("out", "", "output path for the generated corpus")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	data, err := conformancegen.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate conformance corpus: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write conformance corpus: %v\n", err)
		os.Exit(1)
	}
}
