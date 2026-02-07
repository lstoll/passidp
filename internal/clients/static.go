package clients

import (
	"context"
	"fmt"
	"slices"
	"time"

	"lds.li/oauth2ext/oauth2as"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oidcsvr"
)

var _ oauth2as.ClientSource = &StaticClients{}

// StaticClients implements the oauth2as.ClientSource against a static list of clients.
// The type is tagged, to enable loading from JSON/YAML.
type StaticClients struct {
	// Clients is the list of clients
	Clients []config.Client `json:"clients"`
}

type StaticClient struct {
	configClient config.Client
}

func (c *StaticClient) UseOverrideSubject() bool {
	return c.configClient.UseOverrideSubject
}

func (c *StaticClient) GrantValidity() *time.Duration {
	if c.configClient.GrantValidity != 0 {
		return ptr(c.configClient.GrantValidity.Duration())
	}
	return nil
}

func (c *StaticClient) AccessIDTokenValidity() *time.Duration {
	if c.configClient.TokenValidity != 0 {
		return ptr(c.configClient.TokenValidity.Duration())
	}
	return nil
}

func (c *StaticClient) RefreshValidity() *time.Duration {
	if c.configClient.RefreshValidity != 0 {
		return ptr(c.configClient.RefreshValidity.Duration())
	}
	return nil
}

func (c *StaticClient) DPoPRefreshValidity() *time.Duration {
	if c.configClient.DPoPRefreshValidity != 0 {
		return ptr(c.configClient.DPoPRefreshValidity.Duration())
	}
	return nil
}

func (c *StaticClient) RequiredGroups() []string {
	return c.configClient.RequiredGroups
}

// GetClient returns the client with the given ID, or nil if it doesn't exist.
func (c *StaticClients) GetClient(clientID string) (oidcsvr.Client, bool) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			return &StaticClient{configClient: cl}, true
		}
	}
	return nil, false
}

func (c *StaticClients) IsValidClientID(_ context.Context, clientID string) (ok bool, err error) {
	return slices.ContainsFunc(c.Clients, func(c config.Client) bool {
		return c.ID == clientID
	}), nil
}

func (c *StaticClients) ClientOpts(_ context.Context, clientID string) ([]oauth2as.ClientOpt, error) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			opts := []oauth2as.ClientOpt{}
			if cl.SkipPKCE {
				opts = append(opts, oauth2as.ClientOptSkipPKCE())
			}
			if cl.UseRS256 {
				opts = append(opts, oauth2as.ClientOptSigningAlg("RS256"))
			} else {
				// TODO - we should make the default configurable on oauth2as.Server
				opts = append(opts, oauth2as.ClientOptSigningAlg("ES256"))
			}
			return opts, nil
		}
	}
	return nil, nil
}

func (c *StaticClients) ClientSecrets(_ context.Context, clientID string) ([]string, error) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			return cl.Secrets, nil
		}
	}
	return nil, fmt.Errorf("client %s not found", clientID)
}

func (c *StaticClients) RedirectURIs(_ context.Context, clientID string) ([]string, error) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			return cl.RedirectURLs, nil
		}
	}
	return nil, fmt.Errorf("client %s not found", clientID)
}
