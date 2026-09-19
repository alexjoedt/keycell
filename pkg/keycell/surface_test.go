package keycell

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSurfaceHasNoAge parses the package and prints every exported
// declaration: none may mention an age type (ADR 0007).
func TestSurfaceHasNoAge(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	age := regexp.MustCompile(`\bage\.|filippo\.io`)
	var seen int
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			if !exported(decl) {
				continue
			}
			var buf bytes.Buffer
			if err := printer.Fprint(&buf, fset, decl); err != nil {
				t.Fatal(err)
			}
			seen++
			if age.Match(buf.Bytes()) {
				t.Errorf("exported declaration mentions age:\n%s", buf.String())
			}
		}
	}
	if seen < 10 {
		t.Fatalf("only %d exported declarations found, parse went wrong", seen)
	}
}

func exported(decl ast.Decl) bool {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil {
			return d.Name.IsExported() && recvExported(d.Recv)
		}
		return d.Name.IsExported()
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					return true
				}
			case *ast.ValueSpec:
				for _, n := range s.Names {
					if n.IsExported() {
						return true
					}
				}
			}
		}
	}
	return false
}

func recvExported(recv *ast.FieldList) bool {
	for _, f := range recv.List {
		expr := f.Type
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		if id, ok := expr.(*ast.Ident); ok && id.IsExported() {
			return true
		}
	}
	return false
}
