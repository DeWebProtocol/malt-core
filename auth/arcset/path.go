package arcset

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrEmptyPath is returned when a raw binding path canonicalizes to the
	// empty path. Empty paths are valid for traversal state, but not for an arc
	// binding key.
	ErrEmptyPath = errors.New("path must not be empty")

	// ErrDuplicatePath is returned when two raw paths canonicalize to the same
	// path but carry different targets.
	ErrDuplicatePath = errors.New("duplicate canonical path")
)

// PathError describes a raw path that cannot be used as an arc binding key.
type PathError struct {
	Path string
	Err  error
}

func (e *PathError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Path == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%q: %v", e.Path, e.Err)
}

func (e *PathError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Path is a canonical arc path used inside MALT core components.
// The zero value represents an empty path.
type Path string

// PayloadPath is the standard coordinate used by layouts that bind a semantic
// object to payload data. Generic maps may omit or delete this coordinate;
// layouts such as UnixFS define when it is required.
const PayloadPath Path = "@payload"

// CanonicalizePath normalizes a raw path into a stable arcset form.
// It removes empty segments and joins the remaining segments with '/'.
func CanonicalizePath(path string) Path {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		filtered = append(filtered, part)
	}
	return Path(strings.Join(filtered, "/"))
}

// NewPath canonicalizes a raw path for use as an arc binding key.
func NewPath(raw string) (Path, error) {
	canonical := CanonicalizePath(raw)
	if canonical.IsEmpty() {
		return "", &PathError{Path: raw, Err: ErrEmptyPath}
	}
	return canonical, nil
}

// String returns the canonical string form of the path.
func (p Path) String() string {
	return string(p)
}

// IsEmpty reports whether the path is empty.
func (p Path) IsEmpty() bool {
	return p == ""
}

// Segments returns the canonical path split into segments.
func (p Path) Segments() []string {
	if p.IsEmpty() {
		return nil
	}
	return strings.Split(p.String(), "/")
}

// HasPrefix reports whether prefix is a full-segment prefix of p.
func (p Path) HasPrefix(prefix Path) bool {
	if prefix.IsEmpty() {
		return true
	}
	if p == prefix {
		return true
	}

	s := p.String()
	pre := prefix.String()
	return strings.HasPrefix(s, pre+"/")
}

// Consume removes prefix from the front of p when prefix is a full-segment prefix.
// It returns the remaining canonical path and whether the consumption succeeded.
func (p Path) Consume(prefix Path) (Path, bool) {
	if prefix.IsEmpty() {
		return p, true
	}
	if p == prefix {
		return "", true
	}
	if !p.HasPrefix(prefix) {
		return "", false
	}

	s := p.String()
	pre := prefix.String()
	return Path(s[len(pre)+1:]), true
}
