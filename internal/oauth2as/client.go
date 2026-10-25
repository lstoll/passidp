package oauth2as

import (
	"context"
	"fmt"
	"net/url"

	"lds.li/oauth2ext/jwt"
)

// Client describes a registered OAuth client.
type Client struct {
	// ID is the client identifier.
	ID string
	// RedirectURIs is the list of valid redirect URIs. They are compared for an
	// exact match, with the exception of loopback addresses, which can have a
	// variable port (https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
	RedirectURIs []string

	// Authentication. Exactly one method applies: PrivateKeyJWT if set,
	// otherwise Public (PKCE only, no secret), otherwise Secrets. Combining
	// Secrets with PrivateKeyJWT or Public is invalid.

	// Secrets is the list of valid client secrets, for confidential clients
	// using client_secret authentication.
	Secrets []string
	// Public marks the client as public. Public clients authenticate the
	// authorization-code exchange with PKCE instead of a client secret.
	Public bool
	// PrivateKeyJWT configures private_key_jwt authentication. The key set is
	// a stable handle and may be updated with Replace.
	PrivateKeyJWT *jwt.VerificationKeySet

	// SkipPKCE disables the PKCE requirement. Not allowed with Public.
	SkipPKCE bool
	// IDTokenSigningAlgorithm overrides the server default when set.
	IDTokenSigningAlgorithm jwt.Algorithm
}

// validate checks that the client's configuration is internally consistent.
func (c *Client) validate() error {
	if c.Public && c.SkipPKCE {
		return fmt.Errorf("public clients cannot skip PKCE")
	}
	if c.Public && c.PrivateKeyJWT != nil {
		return fmt.Errorf("public clients cannot use private_key_jwt")
	}
	if c.Public && len(c.Secrets) > 0 {
		return fmt.Errorf("public clients cannot have client secrets")
	}
	if c.PrivateKeyJWT != nil && len(c.Secrets) > 0 {
		return fmt.Errorf("private_key_jwt clients cannot have client secrets")
	}
	return nil
}

// ClientSource looks up clients.
type ClientSource interface {
	// Client returns the client with the given ID, or (nil, nil) if there is
	// none.
	Client(ctx context.Context, clientID string) (*Client, error)
}

// isValidRedirectURI compares a redirect URI from a request against a list of
// registered URIs, conforming to OAuth 2.1 specifications.
//
// It performs a simple string comparison as required by RFC 3986. It also
// handles the special case for native app loopback IP-literal URIs
// (http://127.0.0.1 or http://[::1]) where the port number can be variable,
// as specified in RFC 8252, Section 7.3. The registered address literal and
// all other URI components must still match exactly.
//
// - redirectURI: The URI from the incoming authorization request.
// - registeredURIs: A slice of URIs registered for the client.
//
// Returns true if a valid match is found, otherwise false.
func isValidRedirectURI(redirectURI string, registeredURIs []string) bool {
	isLoopbackHost := func(hostname string) bool {
		return hostname == "127.0.0.1" || hostname == "::1"
	}

	for _, registeredURI := range registeredURIs {
		// direct string comparison
		if redirectURI == registeredURI {
			return true
		}

		// check for the loopback exception
		reqURL, err := url.Parse(redirectURI)
		if err != nil {
			continue
		}

		regURL, err := url.Parse(registeredURI)
		if err != nil {
			continue
		}

		// Check if both are HTTP loopback URIs.
		isReqLoopback := reqURL.Scheme == "http" && isLoopbackHost(reqURL.Hostname())
		isRegLoopback := regURL.Scheme == "http" && isLoopbackHost(regURL.Hostname())

		if isReqLoopback && isRegLoopback && reqURL.Hostname() == regURL.Hostname() {
			// For loopback URIs, only the port may vary. Retain the registered
			// address literal so IPv4 and IPv6 loopback endpoints cannot be
			// substituted for one another.
			reqURL.Host = reqURL.Hostname()
			regURL.Host = regURL.Hostname()

			if reqURL.String() == regURL.String() {
				return true
			}
		}
	}

	// No match found after checking all registered URIs.
	return false
}
