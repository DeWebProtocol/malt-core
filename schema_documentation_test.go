package malt_test

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/artifact"
	"github.com/dewebprotocol/malt-core/protocol"
)

var documentedSchemaName = regexp.MustCompile("`([a-z0-9-]+\\.schema\\.json)`")

func TestEmbeddedSchemaCatalogsMatchDocumentation(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		marker string
		want   []string
	}{
		{
			name:   "protocol",
			path:   "docs/spec/README.md",
			marker: "protocol",
			want:   protocol.SchemaNames(),
		},
		{
			name:   "artifact",
			path:   "docs/spec/artifacts.md",
			marker: "artifact",
			want:   artifact.SchemaNames(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := readDocumentedSchemaCatalog(t, test.path, test.marker)
			want := append([]string(nil), test.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s schema catalog mismatch\n got: %v\nwant: %v", test.path, got, want)
			}
		})
	}
}

func readDocumentedSchemaCatalog(t *testing.T, path, marker string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	startMarker := "<!-- schema-catalog:" + marker + ":start -->"
	endMarker := "<!-- schema-catalog:" + marker + ":end -->"
	document := string(data)
	if strings.Count(document, startMarker) != 1 || strings.Count(document, endMarker) != 1 {
		t.Fatalf("%s must contain exactly one %q and one %q marker", path, startMarker, endMarker)
	}
	start := strings.Index(document, startMarker) + len(startMarker)
	end := strings.Index(document, endMarker)
	if end <= start {
		t.Fatalf("%s has an invalid %s schema catalog marker order", path, marker)
	}

	matches := documentedSchemaName.FindAllStringSubmatch(document[start:end], -1)
	if len(matches) == 0 {
		t.Fatalf("%s %s schema catalog is empty", path, marker)
	}
	names := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		name := match[1]
		if _, exists := seen[name]; exists {
			t.Fatalf("%s %s schema catalog repeats %q", path, marker, name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
