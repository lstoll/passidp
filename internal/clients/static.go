package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tailscale/hujson"
	"lds.li/oauth2ext/oauth2as"
)

// StaticClients implements the oauth2as.ClientSource against a static list of clients.
// The type is tagged, to enable loading from JSON/YAML.
type StaticClients struct {
	// Clients is the list of clients
	Clients []Client `json:"clients"`
}

func ParseStaticClients(file []byte) (*StaticClients, error) {
	scb := []byte(os.Expand(string(file), getenvWithDefault))
	scb, err := hujson.Standardize(scb)
	if err != nil {
		return nil, fmt.Errorf("standardize config: %w", err)
	}
	var sc StaticClients
	dec := json.NewDecoder(bytes.NewReader(scb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &sc, nil
}

func (c *StaticClients) Validate() error {
	var validErr error
	for ci, cl := range c.Clients {
		if cl.ID == "" {
			validErr = errors.Join(validErr, fmt.Errorf("client %s missing ID", cl.ID))
		}
		if len(cl.Secrets) == 0 && !cl.Public {
			validErr = errors.Join(validErr, fmt.Errorf("non-public client %s missing client secrets", cl.ID))
		}
		if len(cl.RedirectURLs) == 0 {
			validErr = errors.Join(validErr, fmt.Errorf("client %s missing redirect URLs", cl.ID))
		}
		if cl.TokenValidity != "" {
			tokenValidity, err := time.ParseDuration(cl.TokenValidity)
			if err != nil {
				validErr = errors.Join(validErr, fmt.Errorf("client %s invalid token validity: %w", cl.ID, err))
			}
			c.Clients[ci].ParsedTokenValidity = tokenValidity
		}
	}
	return validErr
}

// Client represents an individual oauth2/oidc client.
type Client struct {
	// ID is the identifier for this client, corresponds to the client ID.
	ID string `json:"id"`
	// Secrets is a list of valid client secrets for this client. At least
	// one secret is required, unless the client is Public and uses PKCE.
	Secrets []string `json:"clientSecrets"`
	// RedirectURLS is a list of valid redirect URLs for this client. At least
	// one is required These are an exact match, with the exception of localhost
	// being able to use any port. The loopback address must be used, the
	// hostname is disallowed.
	RedirectURLs []string `json:"redirectURLs"`
	// Public indicates that this client is public. A "public" client is one who
	// can't keep their credentials confidential. These will not be required to use
	// a client secret.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
	Public bool `json:"public"`
	// SkipPKCE indicates that this client should not be required to use PKCE.
	SkipPKCE bool `json:"skipPKCE"`
	// UseOverrideSubject indicates that this client should use the override
	// subject for tokens/userinfo, rather than the user's ID
	UseOverrideSubject bool `json:"useOverrideSubject"`
	// UseRS256 indicates that this client should use RS256 for tokens/userinfo,
	// rather than defaulting to ES256
	UseRS256 bool `json:"useRS256"`
	// TokenValidity overrides the default valitity time for ID/access tokens.
	// Go duration format.
	TokenValidity string `json:"tokenValidity"`
	// RequiredGroups is a list of group names that the user must be a member of
	// to access this client. If empty, no group membership is required.
	RequiredGroups []string `json:"requiredGroups"`

	// ParsedTokenValidity is the parsed token validity time, this happens at
	// validation time.
	ParsedTokenValidity time.Duration `json:"-"`
}

// GetClient returns the client with the given ID, or nil if it doesn't exist.
func (c *StaticClients) GetClient(clientID string) (*Client, bool) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			return &cl, true
		}
	}
	return nil, false
}

func (c *StaticClients) IsValidClientID(_ context.Context, clientID string) (ok bool, err error) {
	return slices.ContainsFunc(c.Clients, func(c Client) bool {
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

// getenvWithDefault maps FOO:-default to $FOO or default if $FOO is unset or
// null.
func getenvWithDefault(key string) string {
	parts := strings.SplitN(key, ":-", 2)
	val := os.Getenv(parts[0])
	if val == "" && len(parts) == 2 {
		val = parts[1]
	}
	return val
}
