package clients

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"slices"

	"lds.li/oauth2ext/jwt"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oauth2as"
)

var _ oauth2as.ClientSource = &StaticClients{}

// StaticClients implements the oauth2as.ClientSource against a static list of clients.
// The type is tagged, to enable loading from JSON/YAML.
type StaticClients struct {
	remoteJWKS []*RemoteJWKS
	index      map[string]*oauth2as.Client
}

// NewStaticClients prepares static clients. It does not fetch remote JWKS
// documents; run each of [StaticClients.RemoteJWKS] to load and refresh them.
func NewStaticClients(configured []config.Client) (*StaticClients, error) {
	clients := &StaticClients{
		index: make(map[string]*oauth2as.Client, len(configured)),
	}
	verificationKeys := make(map[string]*jwt.VerificationKeySet)
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
			verificationKeys[cl.ID] = set
		}
		if cl.JWKSURL != "" {
			if u, err := url.Parse(cl.JWKSURL); err != nil || u.Scheme != "https" || u.Host == "" {
				return nil, fmt.Errorf("client %s jwksURL must be an absolute https URL", cl.ID)
			}
			set, err := jwt.NewVerificationKeySet()
			if err != nil {
				return nil, fmt.Errorf("client %s: create verification key set: %w", cl.ID, err)
			}
			verificationKeys[cl.ID] = set
			clients.remoteJWKS = append(clients.remoteJWKS, &RemoteJWKS{ClientID: cl.ID, URL: cl.JWKSURL, keys: set})
		}
		client := &oauth2as.Client{
			ID:                      cl.ID,
			RedirectURIs:            slices.Clone(cl.RedirectURLs),
			Public:                  cl.Public,
			SkipPKCE:                cl.SkipPKCE,
			IDTokenSigningAlgorithm: jwt.ES256,
			ClaimsPolicy:            cl.ClaimsPolicy,
			AuthorizationPolicy:     cl.AuthorizationPolicy,
			GrantValidity:           cl.GrantValidity.Duration(),
			TokenValidity:           cl.TokenValidity.Duration(),
			RefreshValidity:         cl.RefreshValidity.Duration(),
			DPoPRefreshValidity:     cl.DPoPRefreshValidity.Duration(),
		}
		if cl.UseRS256 {
			client.IDTokenSigningAlgorithm = jwt.RS256
		}
		if keys := verificationKeys[cl.ID]; keys != nil {
			client.PrivateKeyJWT = keys
		} else {
			client.Secrets = slices.Clone(cl.Secrets)
		}
		clients.index[cl.ID] = client
	}
	return clients, nil
}

// RemoteJWKS returns the remote key loaders that must be run for clients
// configured with a jwksURL.
func (c *StaticClients) RemoteJWKS() []*RemoteJWKS {
	return slices.Clone(c.remoteJWKS)
}

// Client implements oauth2as.ClientSource.
func (c *StaticClients) Client(_ context.Context, clientID string) (*oauth2as.Client, error) {
	client := c.index[clientID]
	if client == nil {
		return nil, nil
	}
	copy := *client
	copy.RedirectURIs = slices.Clone(client.RedirectURIs)
	copy.Secrets = slices.Clone(client.Secrets)
	return &copy, nil
}
