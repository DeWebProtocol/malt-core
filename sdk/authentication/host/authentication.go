package host

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
)

func (c *Computer) PrepareAuthentication(ctx context.Context, data []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("writer is not initialized")
	}
	state, err := protocol.DecodeAuthenticationState(data)
	if err != nil {
		return nil, err
	}
	e, err := c.authenticationEngine()
	if err != nil {
		return nil, err
	}
	candidate, err := authentication.Prepare(ctx, e, state)
	if err != nil {
		return nil, err
	}
	return json.Marshal(candidate)
}

func (c *Computer) authenticationEngine() (*engine.Engine, error) {
	if c == nil || c.authEngine == nil {
		return nil, fmt.Errorf("writer is not initialized")
	}
	return c.authEngine, nil
}
func (c *Computer) UpdateAuthentication(ctx context.Context, baseJSON, stateJSON []byte) ([]byte, error) {
	base, err := protocol.DecodeAuthenticationCandidate(baseJSON)
	if err != nil {
		return nil, err
	}
	state, err := protocol.DecodeAuthenticationState(stateJSON)
	if err != nil {
		return nil, err
	}
	e, err := c.authenticationEngine()
	if err != nil {
		return nil, err
	}
	candidate, err := authentication.PrepareUpdate(ctx, e, base, state)
	if err != nil {
		return nil, err
	}
	return json.Marshal(candidate)
}

func encodeAuthenticationHandle(h authentication.Handle) ([]byte, error) {
	return json.Marshal(struct {
		Handle string `json:"handle"`
		Root   string `json:"root"`
	}{h.ID, h.Root.String()})
}
func (c *Computer) CreateAuthentication(ctx context.Context, data []byte) ([]byte, error) {
	state, err := protocol.DecodeAuthenticationState(data)
	if err != nil {
		return nil, err
	}
	if _, err := c.authenticationEngine(); err != nil {
		return nil, err
	}
	h, err := c.authSession.Build(ctx, state)
	if err != nil {
		return nil, err
	}
	return encodeAuthenticationHandle(h)
}
func (c *Computer) ImportAuthentication(ctx context.Context, data []byte) ([]byte, error) {
	candidate, err := protocol.DecodeAuthenticationCandidate(data)
	if err != nil {
		return nil, err
	}
	if _, err := c.authenticationEngine(); err != nil {
		return nil, err
	}
	h, err := c.authSession.Import(ctx, candidate)
	if err != nil {
		return nil, err
	}
	return encodeAuthenticationHandle(h)
}
func (c *Computer) ApplyAuthentication(ctx context.Context, handle string, data []byte) ([]byte, error) {
	delta, err := protocol.DecodeAuthenticationDelta(data)
	if err != nil {
		return nil, err
	}
	changes, err := delta.CoreChanges()
	if err != nil {
		return nil, err
	}
	if _, err := c.authenticationEngine(); err != nil {
		return nil, err
	}
	h, err := c.authSession.Apply(ctx, handle, authentication.Delta{Changes: changes, Count: delta.Count, TotalSize: delta.TotalSize})
	if err != nil {
		return nil, err
	}
	return encodeAuthenticationHandle(h)
}
func (c *Computer) ExportAuthentication(ctx context.Context, handle string) ([]byte, error) {
	if _, err := c.authenticationEngine(); err != nil {
		return nil, err
	}
	candidate, err := c.authSession.Export(ctx, handle)
	if err != nil {
		return nil, err
	}
	return json.Marshal(candidate)
}
func (c *Computer) DiscardAuthentication(handle string) error {
	if _, err := c.authenticationEngine(); err != nil {
		return err
	}
	return c.authSession.Discard(handle)
}
func (c *Computer) CloseAuthentication() error {
	if _, err := c.authenticationEngine(); err != nil {
		return err
	}
	c.authSession.Clear()
	return nil
}
