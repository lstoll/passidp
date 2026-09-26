package clients

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"slices"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oidcsvr"
)

var _ oauth2as.ClientSource = &StaticClients{}

// StaticClients implements the oauth2as.ClientSource against a static list of clients.
// The type is tagged, to enable loading from JSON/YAML.
type StaticClients struct {
	// Clients is the list of clients
	Clients          []config.Client `json:"clients"`
	verificationKeys map[string]*jwt.VerificationKeySet
	remoteJWKS       []*RemoteJWKS
}

// NewStaticClients prepares static clients. It does not fetch remote JWKS
// documents; run each of [StaticClients.RemoteJWKS] to load and refresh them.
func NewStaticClients(configured []config.Client) (*StaticClients, error) {
	clients := &StaticClients{
		Clients:          configured,
		verificationKeys: make(map[string]*jwt.VerificationKeySet),
	}
	clientIDs := make(map[string]struct{}, len(configured))
	for _, cl := range configured {
		if cl.ID == "" {
			return nil, fmt.Errorf("static client ID is required")
		}
		if _, found := clientIDs[cl.ID]; found {
			return nil, fmt.Errorf("duplicate static client ID %s", cl.ID)
		}
		clientIDs[cl.ID] = struct{}{}
		hasPEMKeys := len(cl.ClientJWTPublicKeys) > 0
		hasJWKS := cl.JWKSURL != ""
		if hasPEMKeys && hasJWKS {
			return nil, fmt.Errorf("client %s cannot configure both clientJWTPublicKeys and jwksURL", cl.ID)
		}
		if (hasPEMKeys || hasJWKS) && (cl.Public || len(cl.Secrets) > 0) {
			return nil, fmt.Errorf("client %s private_key_jwt cannot be combined with public client authentication or client secrets", cl.ID)
		}
		if len(cl.ClientJWTPublicKeys) > 0 {
			keys := make([]jwt.VerificationKey, 0, len(cl.ClientJWTPublicKeys))
			for i, configuredKey := range cl.ClientJWTPublicKeys {
				block, rest := pem.Decode([]byte(configuredKey.PEM))
				if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
					return nil, fmt.Errorf("client %s key %d must contain exactly one PKIX PUBLIC KEY PEM block", cl.ID, i)
				}
				publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("client %s key %d: parse public key: %w", cl.ID, i, err)
				}
				key, err := jwt.NewVerificationKey(publicKey, "", configuredKey.KeyID)
				if err != nil {
					return nil, fmt.Errorf("client %s key %d: %w", cl.ID, i, err)
				}
				if key.Algorithm != jwt.ES256 && key.Algorithm != jwt.RS256 {
					return nil, fmt.Errorf("client %s key %d: unsupported private_key_jwt algorithm %s", cl.ID, i, key.Algorithm)
				}
				keys = append(keys, key)
			}
			set, err := jwt.NewVerificationKeySet(keys...)
			if err != nil {
				return nil, fmt.Errorf("client %s: invalid client JWT keys: %w", cl.ID, err)
			}
			clients.verificationKeys[cl.ID] = set
		}
		if cl.JWKSURL != "" {
			if u, err := url.Parse(cl.JWKSURL); err != nil || u.Scheme != "https" || u.Host == "" {
				return nil, fmt.Errorf("client %s jwksURL must be an absolute https URL", cl.ID)
			}
			set, err := jwt.NewVerificationKeySet()
			if err != nil {
				return nil, fmt.Errorf("client %s: create verification key set: %w", cl.ID, err)
			}
			clients.verificationKeys[cl.ID] = set
			clients.remoteJWKS = append(clients.remoteJWKS, &RemoteJWKS{ClientID: cl.ID, URL: cl.JWKSURL, keys: set})
		}
	}
	return clients, nil
}

// RemoteJWKS returns the remote key loaders that must be run for clients
// configured with a jwksURL.
func (c *StaticClients) RemoteJWKS() []*RemoteJWKS {
	return slices.Clone(c.remoteJWKS)
}

type StaticClient struct {
	configClient config.Client
}

func (c *StaticClient) ClaimsPolicy() string {
	return c.configClient.ClaimsPolicy
}

func (c *StaticClient) AuthorizationPolicy() string {
	return c.configClient.AuthorizationPolicy
}

func (c *StaticClient) GrantValidity() *time.Duration {
	if c.configClient.GrantValidity != 0 {
		return new(c.configClient.GrantValidity.Duration())
	}
	return nil
}

func (c *StaticClient) AccessIDTokenValidity() *time.Duration {
	if c.configClient.TokenValidity != 0 {
		return new(c.configClient.TokenValidity.Duration())
	}
	return nil
}

func (c *StaticClient) RefreshValidity() *time.Duration {
	if c.configClient.RefreshValidity != 0 {
		return new(c.configClient.RefreshValidity.Duration())
	}
	return nil
}

func (c *StaticClient) DPoPRefreshValidity() *time.Duration {
	if c.configClient.DPoPRefreshValidity != 0 {
		return new(c.configClient.DPoPRefreshValidity.Duration())
	}
	return nil
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
			if cl.Public {
				opts = append(opts, oauth2as.ClientOptPublic())
			}
			if cl.SkipPKCE {
				opts = append(opts, oauth2as.ClientOptSkipPKCE())
			}
			if keys := c.verificationKeys[cl.ID]; keys != nil {
				opts = append(opts, oauth2as.ClientOptPrivateKeyJWT(keys))
			}
			signingAlgorithm := jwt.ES256
			if cl.UseRS256 {
				signingAlgorithm = jwt.RS256
			}
			opts = append(opts, oauth2as.ClientOptIDTokenSigningAlgorithm(signingAlgorithm))
			return opts, nil
		}
	}
	return nil, nil
}

func (c *StaticClients) ClientSecrets(_ context.Context, clientID string) ([]string, error) {
	for _, cl := range c.Clients {
		if cl.ID == clientID {
			if c.verificationKeys[cl.ID] != nil {
				return nil, nil
			}
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
