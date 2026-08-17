package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dewebprotocol/malt-core/internal/conformancegen"
)

func main() {
	corpus := flag.String("corpus", "resolve-read", "corpus to generate: resolve-read, map-proof, or client-root")
	out := flag.String("out", "", "output path for the generated corpus")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	var (
		data []byte
		err  error
	)
	switch *corpus {
	case "resolve-read":
		data, err = conformancegen.Generate()
	case "map-proof":
		data, err = conformancegen.GenerateMapProof()
	case "client-root":
		data, err = conformancegen.GenerateClientRoot()
	default:
		fmt.Fprintf(os.Stderr, "unsupported conformance corpus %q\n", *corpus)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate %s conformance corpus: %v\n", *corpus, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write conformance corpus: %v\n", err)
		os.Exit(1)
	}
}
