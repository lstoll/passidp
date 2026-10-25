package oauth2as

import (
	"context"
	"fmt"
	"net/url"

	"lds.li/oauth2ext/jwt"
)

type clientOpts struct {
	skipPKCE                bool
	idTokenSigningAlgorithm jwt.Algorithm
	public                  bool
	privateKeyJWT           *jwt.VerificationKeySet
	privateKeyJWTConfigured bool
}

// ClientOpt is a flag that can be set on a given client, to adjust various
// behaviours.
type ClientOpt func(opts *clientOpts)

// ClientOptSkipPKCE indicates that the client is not required to use PKCE. It
// must not be combined with [ClientOptPublic].
func ClientOptSkipPKCE() ClientOpt {
	return func(opts *clientOpts) {
		opts.skipPKCE = true
	}
}

// ClientOptIDTokenSigningAlgorithm selects the ID-token signing algorithm for
// a client that cannot use the server default.
func ClientOptIDTokenSigningAlgorithm(algorithm jwt.Algorithm) ClientOpt {
	return func(opts *clientOpts) {
		opts.idTokenSigningAlgorithm = algorithm
	}
}

// ClientOptPublic marks a client as public. Public clients authenticate the
// authorization-code exchange with PKCE instead of a client secret. It must
// not be combined with [ClientOptSkipPKCE].
func ClientOptPublic() ClientOpt {
	return func(opts *clientOpts) {
		opts.public = true
	}
}

// ClientOptPrivateKeyJWT configures private_key_jwt authentication for a
// client. The key set is a stable handle and may be updated with Replace.
// It cannot be combined with ClientOptPublic or client-secret authentication.
func ClientOptPrivateKeyJWT(keys *jwt.VerificationKeySet) ClientOpt {
	return func(opts *clientOpts) {
		opts.privateKeyJWT = keys
		opts.privateKeyJWTConfigured = true
	}
}

func applyClientOpts(opts []ClientOpt) (clientOpts, error) {
	var result clientOpts
	for _, opt := range opts {
		opt(&result)
	}
	if result.public && result.skipPKCE {
		return clientOpts{}, fmt.Errorf("public clients cannot skip PKCE")
	}
	if result.public && result.privateKeyJWT != nil {
		return clientOpts{}, fmt.Errorf("public clients cannot use private_key_jwt")
	}
	if result.privateKeyJWTConfigured && result.privateKeyJWT == nil {
		return clientOpts{}, fmt.Errorf("private_key_jwt requires verification keys")
	}
	return result, nil
}

// ClientSource is used for validating client information for the general flow
type ClientSource interface {
	// IsValidClientID should return true if the passed client ID is valid
	IsValidClientID(_ context.Context, clientID string) (ok bool, err error)
	// ClientSecrets should return the list of valid client secrets for the
	// given client.
	ClientSecrets(_ context.Context, clientID string) ([]string, error)
	// ValidateRedirectURI should return the list of valid redirect URIs. They
	// will be compared for an exact match, with the exception of loopback
	// addresses, which can have a variable port
	// (https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
	RedirectURIs(_ context.Context, clientID string) ([]string, error)
	// ClientOpts returns the list of options for this client. See ClientOpt.
	ClientOpts(_ context.Context, clientID string) ([]ClientOpt, error)
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
