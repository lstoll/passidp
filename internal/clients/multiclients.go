package clients

import (
	"context"

	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/web"
)

var _ oauth2as.ClientSource = (*MultiClients)(nil)

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

// Client implements oauth2as.ClientSource. Static clients take precedence: if
// the static source has the ID, it is returned and the dynamic source is never
// consulted. Otherwise a same-ID dynamic client could change the
// authentication mode of a static client (e.g. private_key_jwt to secret).
func (m *MultiClients) Client(ctx context.Context, clientID string) (*oauth2as.Client, error) {
	if m.Static != nil {
		client, err := m.Static.Client(ctx, clientID)
		if err != nil || client != nil {
			return client, err
		}
	}
	if m.Dynamic != nil {
		return m.Dynamic.Client(ctx, clientID)
	}
	return nil, nil
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
