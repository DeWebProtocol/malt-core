package arcset

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrEmptyPath is returned when a raw binding path canonicalizes to the
	// empty path. An arc binding key must be nonempty.
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

// Path is a canonical ArcSet materializer key, not a typed query or traversal.
// The zero value represents an empty path.
type Path string

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
