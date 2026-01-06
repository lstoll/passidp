package clients

import (
	"context"

	"lds.li/oauth2ext/oauth2as"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/web"
	"lds.li/webauthn-oidc-idp/internal/oidcsvr"
)

// MultiClients combines multiple client sources, with static clients taking precedence
type MultiClients struct {
	Static  *StaticClients
	Dynamic *DynamicClients
}

// NewMultiClients creates a new MultiClients instance
func NewMultiClients(static *StaticClients, dynamic *DynamicClients) *MultiClients {
	return &MultiClients{
		Static:  static,
		Dynamic: dynamic,
	}
}

// GetClient implements the ClientSource interface
// Static clients take precedence over dynamic clients
func (m *MultiClients) GetClient(clientID string) (oidcsvr.Client, bool) {
	// First try static clients
	if client, found := m.Static.GetClient(clientID); found {
		return client, true
	}

	// Then try dynamic clients
	if client, found := m.Dynamic.GetClient(clientID); found {
		return client, true
	}

	return nil, false
}

// IsValidClientID implements oauth2as.ClientSource
func (m *MultiClients) IsValidClientID(ctx context.Context, clientID string) (bool, error) {
	// Check static clients first
	if ok, err := m.Static.IsValidClientID(ctx, clientID); err != nil {
		return false, err
	} else if ok {
		return true, nil
	}

	// Then check dynamic clients
	return m.Dynamic.IsValidClientID(ctx, clientID)
}

// ClientOpts implements oauth2as.ClientSource
func (m *MultiClients) ClientOpts(ctx context.Context, clientID string) ([]oauth2as.ClientOpt, error) {
	// Check static clients first
	if opts, err := m.Static.ClientOpts(ctx, clientID); err != nil {
		return nil, err
	} else if len(opts) > 0 {
		return opts, nil
	}

	// Then check dynamic clients
	return m.Dynamic.ClientOpts(ctx, clientID)
}

// ValidateClientSecret implements oauth2as.ClientSource
func (m *MultiClients) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) (bool, error) {
	// Check static clients first
	if ok, err := m.Static.ValidateClientSecret(ctx, clientID, clientSecret); err == nil {
		return ok, nil
	}

	// Then check dynamic clients
	return m.Dynamic.ValidateClientSecret(ctx, clientID, clientSecret)
}

// RedirectURIs implements oauth2as.ClientSource
func (m *MultiClients) RedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	// Check static clients first
	if uris, err := m.Static.RedirectURIs(ctx, clientID); err == nil && len(uris) > 0 {
		return uris, nil
	}

	// Then check dynamic clients
	return m.Dynamic.RedirectURIs(ctx, clientID)
}

// GetClientMetadata returns the parsed client registration metadata for a given client ID
// This is only available for dynamic clients
func (m *MultiClients) GetClientMetadata(ctx context.Context, clientID string) (*oidcclientreg.ClientRegistrationRequest, error) {
	// Only dynamic clients have metadata
	return m.Dynamic.GetClientMetadata(ctx, clientID)
}

// AddHandlers adds the dynamic client registration endpoint to the web server
func (m *MultiClients) AddHandlers(r *web.Server) {
	if m.Dynamic != nil {
		m.Dynamic.AddHandlers(r)
	}
}
