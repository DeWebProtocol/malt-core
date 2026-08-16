package graph

import (
	"testing"

	"github.com/dewebprotocol/malt-core/graph/resolver"
	"github.com/dewebprotocol/malt-core/graph/writer"
)

func TestResolverAndWriterImplementGraphPorts(t *testing.T) {
	var _ Resolver = (*resolver.Resolver)(nil)
	var _ MutationWriter = (*writer.Writer)(nil)
	var _ StructureCreator = (*writer.Writer)(nil)
	var _ ReferenceWriter = (*writer.Writer)(nil)
	var _ Writer = (*writer.Writer)(nil)
}
