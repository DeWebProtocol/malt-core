// Package proofwire frames the native ProofList. A field has one definition
// for both directions. The first framing error stops subsequent fields.
package proofwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	cid "github.com/ipfs/go-cid"
)

const MaxBytes = 96 << 20

type Stream struct {
	Reading bool
	Data    []byte // unread input or accumulated output
	Err     error
}

func (s *Stream) Fixed(value []byte, size int) []byte {
	if s.Err != nil {
		return nil
	}
	if s.Reading {
		if size < 0 || size > len(s.Data) {
			s.Err = io.ErrUnexpectedEOF
			return nil
		}
		v := s.Data[:size:size]
		s.Data = s.Data[size:]
		return v
	}
	if len(value) != size || size > MaxBytes-len(s.Data) {
		s.Err = errors.New("invalid ProofList field length")
		return nil
	}
	s.Data = append(s.Data, value...)
	return value
}

func (s *Stream) Uint(v uint64) uint64 {
	if s.Err != nil {
		return 0
	}
	if !s.Reading {
		buf := binary.AppendUvarint(nil, v)
		s.Fixed(buf, len(buf))
		return v
	}
	n, used := binary.Uvarint(s.Data)
	if used <= 0 || used != len(binary.AppendUvarint(nil, n)) {
		s.Err = errors.New("invalid ProofList unsigned varint")
		return 0
	}
	s.Data = s.Data[used:]
	return n
}

func (s *Stream) Blob(v []byte) []byte {
	n := s.Uint(uint64(len(v)))
	if n > MaxBytes {
		s.Err = errors.New("ProofList field exceeds maximum size")
		return nil
	}
	return s.Fixed(v, int(n))
}

func (s *Stream) CID(v cid.Cid) cid.Cid {
	if s.Err != nil {
		return cid.Undef
	}
	if !s.Reading {
		if !v.Defined() {
			s.Err = errors.New("undefined ProofList CID")
			return cid.Undef
		}
		raw := v.Bytes()
		s.Fixed(raw, len(raw))
		return v
	}
	n, value, err := cid.CidFromBytes(s.Data)
	if err != nil || !value.Defined() || n <= 0 || !bytes.Equal(value.Bytes(), s.Data[:n]) {
		s.Err = errors.New("invalid ProofList CID")
		return cid.Undef
	}
	s.Data = s.Data[n:]
	return value
}
