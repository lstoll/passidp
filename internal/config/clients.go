package config

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
	// UseRS256 indicates that this client should use RS256 for tokens/userinfo,
	// rather than defaulting to ES256
	UseRS256 bool `json:"useRS256"`
	// ClaimsPolicy is a CEL expression that can be used to modify the claims
	// for this client.
	ClaimsPolicy string `json:"claimsPolicy"`
	// AuthorizationPolicy is a CEL expression that can be used to determine if
	// a user is authorized to access this client.
	AuthorizationPolicy string `json:"authorizationPolicy"`

	// GrantValidity overrides the default validity time for grants.
	GrantValidity JSONDuration `json:"grantValidity"`
	// TokenValidity overrides the default valitity time for ID/access tokens.
	// Go duration format.
	TokenValidity JSONDuration `json:"tokenValidity"`
	// RefreshValidity overrides the default validity time for refresh tokens.
	// Go duration format. If 0, refresh tokens will not be issued.
	RefreshValidity JSONDuration `json:"refreshValidity,omitempty"`
	// DPoPRefreshValidity overrides the default validity time for refresh tokens
	// when DPoP is used. Go duration format.
	DPoPRefreshValidity JSONDuration `json:"dpopRefreshValidity,omitempty"`
	// RequiredGroups is a list of group names that the user must be a member of
	// to access this client. If empty, no group membership is required. This is a convenience
	// field that will be converted automatically to an AuthorizationPolicy. Both can not be
	// specified at the same time.œ
	RequiredGroups []string `json:"requiredGroups"`
}
