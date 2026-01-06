package clients

import (
	"context"
	"fmt"
	"slices"
	"time"

	"lds.li/oauth2ext/oauth2as"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/oidcsvr"
)

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

func (c *StaticClient) AccessIDTokenValidity() time.Duration {
	return c.configClient.ParsedTokenValidity
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

func (c *StaticClients) ValidateClientSecret(_ context.Context, clientID, clientSecret string) (ok bool, err error) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			if len(cl.Secrets) == 0 && cl.Public {
				return true, nil
			}
			return slices.Contains(cl.Secrets, clientSecret), nil
		}
	}
	return false, fmt.Errorf("client %s not found", clientID)
}

func (c *StaticClients) RedirectURIs(_ context.Context, clientID string) ([]string, error) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			return cl.RedirectURLs, nil
		}
	}
	return nil, fmt.Errorf("client %s not found", clientID)
}
