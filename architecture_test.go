package malt_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath             = "github.com/dewebprotocol/malt-core"
	materializerImportPath = modulePath + "/auth/arcset/materializer"
)

func TestProductionImportBoundaries(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(sourceFile)

	tests := []struct {
		name      string
		dir       string
		recursive bool
		forbidden []string
	}{
		{
			name:      "authentication kernel",
			dir:       filepath.Join(root, "auth"),
			recursive: true,
			forbidden: []string{"graph", "runtime", "storage", "layout", "model", "sdk", "execution", "api", "server", "logger"},
		},
		{
			name:      "graph ports",
			dir:       filepath.Join(root, "graph"),
			recursive: true,
			forbidden: []string{"runtime", "storage", "layout", "model", "sdk", "execution", "api", "server", "logger"},
		},
		{
			name:      "portable mutation contract",
			dir:       filepath.Join(root, "mutation"),
			recursive: true,
			forbidden: []string{"graph", "runtime", "storage", "model", "sdk", "api", "server", "execution", "logger"},
		},
		{
			name:      "execution contract",
			dir:       filepath.Join(root, "execution"),
			recursive: true,
			forbidden: []string{"graph", "runtime", "storage", "model", "sdk", "api", "server", "logger"},
		},
		{
			name:      "client verifier",
			dir:       filepath.Join(root, "sdk", "verifier"),
			recursive: true,
			forbidden: []string{"graph", "runtime", "storage", "model", "api", "server", "execution", "logger"},
		},
		{
			name:      "client writer",
			dir:       filepath.Join(root, "sdk", "writer"),
			recursive: true,
			forbidden: []string{"artifact", "execution", "storage", "layout", "model", "api", "server", "logger", "sdk/verifier"},
		},
		{
			name:      "module facade",
			dir:       root,
			recursive: false,
			forbidden: []string{"graph", "runtime", "storage", "layout", "model", "sdk", "execution", "api", "server", "logger"},
		},
		{
			name:      "artifact contract",
			dir:       filepath.Join(root, "artifact"),
			recursive: true,
			forbidden: []string{"graph", "runtime", "storage", "layout", "model", "sdk", "execution", "api", "server", "logger"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkProductionImports(t, tc.dir, tc.recursive, tc.forbidden)
		})
	}
}

func TestSDKOnlyRepositoryDoesNotReintroduceProductPackages(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(sourceFile)
	for _, name := range []string{
		"api", "config", "daemon", "model", "reference", "runtime", "server", "storage",
		filepath.Join("cmd", "cas"), filepath.Join("cmd", "eval"), filepath.Join("cmd", "malt"),
	} {
		dir := filepath.Join(root, name)
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return filepath.SkipDir
			}
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") {
				t.Errorf("SDK-only core contains product package source %s", path)
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

func TestSDKOnlyRepositoryDoesNotRetainProductResidue(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(sourceFile)
	for _, name := range []string{
		"config.example.json",
		"logger",
		filepath.Join("graph", "querypath"),
	} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("SDK-only core contains product residue %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("inspect forbidden product path %s: %v", path, err)
		}
	}
}

func TestProductionAlgorithmsUseNarrowMaterializerCapabilities(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(sourceFile)
	allowed := filepath.Join(root, "auth", "arcset", "materializer", "memory", "store.go")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if path == allowed || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		usesAggregate, err := importsAggregateMaterializerStore(path, nil)
		if err != nil {
			return err
		}
		if usesAggregate {
			t.Errorf("production algorithm %s depends on aggregate materializer.Store", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregateMaterializerStoreImportDetection(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "default import",
			src: `package fixture

import "github.com/dewebprotocol/malt-core/auth/arcset/materializer"

var _ materializer.Store
`,
			want: true,
		},
		{
			name: "named import alias cannot bypass guard",
			src: `package fixture

import mat "github.com/dewebprotocol/malt-core/auth/arcset/materializer"

var _ mat.Store
`,
			want: true,
		},
		{
			name: "local variable shadowing import alias is not a package reference",
			src: `package fixture

import mat "github.com/dewebprotocol/malt-core/auth/arcset/materializer"

var _ mat.Lookup

type localMaterializer struct {
	Store int
}

func useLocalMaterializer() {
	mat := localMaterializer{}
	_ = mat.Store
}
`,
		},
		{
			name: "dot import is rejected",
			src: `package fixture

import . "github.com/dewebprotocol/malt-core/auth/arcset/materializer"

var _ Store
`,
			want: true,
		},
		{
			name: "narrow capability through alias",
			src: `package fixture

import mat "github.com/dewebprotocol/malt-core/auth/arcset/materializer"

var _ mat.Lookup
`,
		},
		{
			name: "blank import has no aggregate reference",
			src: `package fixture

import _ "github.com/dewebprotocol/malt-core/auth/arcset/materializer"
`,
		},
		{
			name: "text is not a reference",
			src: `package fixture

const description = "materializer.Store"
`,
		},
		{
			name: "unrelated package selector",
			src: `package fixture

import materializer "example.com/another/materializer"

var _ materializer.Store
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := importsAggregateMaterializerStore("fixture.go", tc.src)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("importsAggregateMaterializerStore() = %v, want %v", got, tc.want)
			}
		})
	}
}

// importsAggregateMaterializerStore reports whether a Go source file imports
// the canonical materializer package and selects its aggregate Store contract.
// It uses type information so that a local variable which shadows an import
// alias cannot turn an unrelated Store field selection into a false positive.
func importsAggregateMaterializerStore(filename string, src any) (bool, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, src, 0)
	if err != nil {
		return false, err
	}

	info := &types.Info{
		Uses: make(map[*ast.Ident]types.Object),
	}
	config := &types.Config{
		Importer: newMaterializerGuardImporter(),
		// Files are checked independently from the rest of their package. Missing
		// sibling declarations and unrelated imports may therefore produce type
		// errors, but bindings available in Uses remain valid for this guard.
		Error: func(error) {},
	}
	_, _ = config.Check("architecture/fixture", fileSet, []*ast.File{file}, info)

	usesAggregate := false
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Store" {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		packageName, ok := info.Uses[qualifier].(*types.PkgName)
		if ok && packageName.Imported().Path() == materializerImportPath {
			usesAggregate = true
			return false
		}
		return true
	})
	if usesAggregate {
		return true, nil
	}

	// A dot import has no qualifier. In that case go/types binds an unqualified
	// Store identifier directly to the target package's exported type object.
	for identifier, object := range info.Uses {
		if identifier.Name != "Store" || object.Pkg() == nil {
			continue
		}
		if object.Pkg().Path() == materializerImportPath {
			return true, nil
		}
	}
	return usesAggregate, nil
}

type materializerGuardImporter struct {
	fallback     types.Importer
	materializer *types.Package
}

func newMaterializerGuardImporter() types.Importer {
	materializer := types.NewPackage(materializerImportPath, "materializer")
	for _, name := range []string{
		"Lookup", "Updater", "Snapshotter", "Iterator", "NodeStore",
		"MutableStore", "Store", "BranchingStore",
	} {
		typeName := types.NewTypeName(token.NoPos, materializer, name, nil)
		types.NewNamed(typeName, types.NewInterfaceType(nil, nil).Complete(), nil)
		materializer.Scope().Insert(typeName)
	}
	materializer.MarkComplete()
	return materializerGuardImporter{
		fallback:     importer.Default(),
		materializer: materializer,
	}
}

func (i materializerGuardImporter) Import(importPath string) (*types.Package, error) {
	if importPath == materializerImportPath {
		return i.materializer, nil
	}
	return i.fallback.Import(importPath)
}

func checkProductionImports(t *testing.T, dir string, recursive bool, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != dir && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			for _, layer := range forbidden {
				prefix := modulePath + "/" + layer
				if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
					t.Errorf("%s imports forbidden layer %q", path, importPath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
