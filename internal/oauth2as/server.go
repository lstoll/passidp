package oauth2as

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"lds.li/oauth2ext/clientjwt"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

const (
	// DefaultCodeValidityTime is used if the CodeValidityTime is not
	// configured.
	DefaultCodeValidityTime = 1 * time.Minute
	// DefaultIDTokenValidity is the default IDTokenValidity time.
	DefaultIDTokenValidity = 1 * time.Hour
	// DefaultsAccessTokenValidity is the default AccessTokenValidity time.
	DefaultsAccessTokenValidity = 1 * time.Hour
	// DefaultGrantValidity is the default GrantValidity time.
	DefaultGrantValidity = 1 * time.Hour
)

// Config is used to set the configuration for creating a server instance.
type Config struct {
	// Issuer is the issuer we are serving for.
	Issuer string
	// Storage is the storage backend to use for the server. The logical storage
	// instance must be scoped to this issuer.
	Storage *Storage
	Clients ClientSource
	// Signer signs ID and access tokens using explicit algorithms.
	Signer jwt.Signer
	// VerificationKeys verifies tokens issued by this server and is suitable for direct
	// publication through discovery. Both are stable reloadable handles.
	VerificationKeys *jwt.VerificationKeySet
	// DefaultIDTokenSigningAlgorithm is used unless a trusted per-client option
	// selects another supported algorithm. Defaults to ES256.
	DefaultIDTokenSigningAlgorithm jwt.Algorithm
	// AccessTokenSigningAlgorithm is issuer policy and is never selected by an
	// OAuth client. Defaults to ES256.
	AccessTokenSigningAlgorithm jwt.Algorithm

	// DPoPVerifier is used for verifying DPoP proofs on token and UserInfo
	// requests. It is optional for bearer-only deployments. When absent, DPoP
	// proofs are rejected and DPoP-bound access tokens fail closed at UserInfo.
	DPoPVerifier *dpop.Verifier

	// TokenURL is the token endpoint URL used as the audience for
	// private_key_jwt client assertions. It defaults to Issuer + "/token".
	TokenURL string

	Logger *slog.Logger

	TokenHandler    TokenHandler
	UserinfoHandler UserinfoHandler

	// CodeValidityTime is the maximum time the authorization code is valid,
	// before it is exchanged for a token (code flow). This should be a short
	// value, as the exchange should generally not take long. Defaults to
	// DefaultCodeValidityTime.
	CodeValidityTime time.Duration
	// IDTokenValidity sets the default validity for issued ID tokens. This can
	// be overridden on a per-request basis.
	IDTokenValidity time.Duration
	// AccessTokenValidity sets the default validity for issued access tokens.
	// This can be overridden on a per-request basis. Must be equal or less to
	// the IDTokenValidity time.
	AccessTokenValidity time.Duration
	// RefreshTokenValidity sets the validity for issued refresh tokens. If 0,
	// the service will not issue refresh tokens. The maximum time refresh
	// tokens can be used will also be capped by the GrantValidity.
	RefreshTokenValidity time.Duration
	// GrantValidity sets the maximum lifetime a given grant is valid for. After
	// this time, no more refreshes can be performed. A grant may become invalid
	// before this time if there are no currently valid tokens issued against
	// it. This can be overidden on a per-grant basis. Defaults to
	// [DefaultGrantValidity].
	GrantValidity time.Duration
	// RefreshTokenRotationGracePeriod is the time window where an old refresh
	// token remains valid after being rotated. This helps handle network
	// failures where the client might retry with the old token. Defaults to 0
	// (no grace period).
	RefreshTokenRotationGracePeriod time.Duration
}

type Server struct {
	config Config
	// accessTokenVerifier is bound once to the stable verification-key handle;
	// key-set replacements remain visible through that handle.
	accessTokenVerifier *jwt.Verifier

	logger *slog.Logger

	now func() time.Time
}

func (s *Server) defaultIDTokenSigningAlgorithm() jwt.Algorithm {
	if s.config.DefaultIDTokenSigningAlgorithm == "" {
		return jwt.ES256
	}
	return s.config.DefaultIDTokenSigningAlgorithm
}

func (s *Server) accessTokenSigningAlgorithm() jwt.Algorithm {
	if s.config.AccessTokenSigningAlgorithm == "" {
		return jwt.ES256
	}
	return s.config.AccessTokenSigningAlgorithm
}

func NewServer(c Config) (*Server, error) {
	// perform validations
	if c.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	_, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL %s: %w", c.Issuer, err)
	}

	if c.Storage == nil {
		return nil, fmt.Errorf("storage is required")
	}
	if c.Clients == nil {
		return nil, fmt.Errorf("clients is required")
	}
	if c.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if c.VerificationKeys == nil {
		return nil, fmt.Errorf("verification keys are required")
	}
	if c.DefaultIDTokenSigningAlgorithm == "" {
		c.DefaultIDTokenSigningAlgorithm = jwt.ES256
	}
	if c.AccessTokenSigningAlgorithm == "" {
		c.AccessTokenSigningAlgorithm = jwt.ES256
	}
	if !c.Signer.SupportsAlgorithm(c.DefaultIDTokenSigningAlgorithm) {
		return nil, fmt.Errorf("default ID token signing algorithm %q is not supported by signer", c.DefaultIDTokenSigningAlgorithm)
	}
	if !c.Signer.SupportsAlgorithm(c.AccessTokenSigningAlgorithm) {
		return nil, fmt.Errorf("access token signing algorithm %q is not supported by signer", c.AccessTokenSigningAlgorithm)
	}

	// TODO - relax this with defaults if we can make them work.
	if c.TokenHandler == nil {
		return nil, fmt.Errorf("token handler is required")
	}
	if c.UserinfoHandler == nil {
		return nil, fmt.Errorf("userinfo handler is required")
	}

	// Set defaults

	if c.AccessTokenValidity == 0 {
		c.AccessTokenValidity = DefaultsAccessTokenValidity
	}
	if c.IDTokenValidity == 0 {
		c.IDTokenValidity = DefaultIDTokenValidity
	}
	if c.CodeValidityTime == 0 {
		c.CodeValidityTime = DefaultCodeValidityTime
	}
	if c.GrantValidity == 0 {
		c.GrantValidity = DefaultGrantValidity
	}

	// Validate token validity times
	if c.AccessTokenValidity < 0 {
		return nil, fmt.Errorf("access token validity must be positive")
	}
	if c.IDTokenValidity < 0 {
		return nil, fmt.Errorf("ID token validity must be positive")
	}
	if c.RefreshTokenValidity < 0 {
		return nil, fmt.Errorf("refresh token validity must be positive or zero")
	}
	if c.CodeValidityTime < 0 {
		return nil, fmt.Errorf("code validity time must be positive")
	}
	if c.GrantValidity < 0 {
		return nil, fmt.Errorf("grant validity must be positive")
	}
	if c.RefreshTokenRotationGracePeriod < 0 {
		return nil, fmt.Errorf("refresh token rotation grace period must be positive or zero")
	}
	if c.AccessTokenValidity > c.IDTokenValidity {
		return nil, fmt.Errorf("access token validity (%v) must be equal to or less than ID token validity (%v)", c.AccessTokenValidity, c.IDTokenValidity)
	}

	accessTokenVerifier, err := jwt.NewVerifier(c.VerificationKeys, jwt.ValidationPolicy{
		ExpectedIssuer:    c.Issuer,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []jwt.Algorithm{c.AccessTokenSigningAlgorithm},
		Type:              jwt.TypeExact,
		ExpectedType:      "at+jwt",
		ClockSkew:         jwt.DefaultClockSkew,
		RequireIssuedAt:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid access token verifier policy: %w", err)
	}

	svr := &Server{
		config:              c,
		accessTokenVerifier: accessTokenVerifier,
		logger:              slog.New(slog.DiscardHandler),
		now:                 time.Now,
	}

	if c.Logger != nil {
		svr.logger = c.Logger
	}

	return svr, nil
}

func (s *Server) tokenURL() string {
	if s.config.TokenURL != "" {
		return s.config.TokenURL
	}
	return strings.TrimRight(s.config.Issuer, "/") + "/token"
}

func (s *Server) validateTokenClient(ctx context.Context, req *oauth2proto.TokenRequest, wantClientID string) (*Client, error) {
	// check to see if we're working with the same client
	assertionAttempt := req.ClientAssertion != "" || req.ClientAssertionType != ""
	if (!assertionAttempt && wantClientID != req.ClientID) || (assertionAttempt && req.ClientID != "" && wantClientID != req.ClientID) {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "", Cause: fmt.Errorf("code redeemed for wrong client")}
	}
	clientID := req.ClientID
	if clientID == "" {
		clientID = wantClientID
	}

	client, err := s.config.Clients.Client(ctx, clientID)
	if err != nil {
		return nil, &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get client", Cause: err}
	}
	if client == nil {
		// A grant exists for a client that is no longer registered. This is
		// reported as an internal error, as it was when the client lookup
		// failed.
		return nil, &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get client", Cause: fmt.Errorf("client %s not found", clientID)}
	}
	if err := client.validate(); err != nil {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "invalid client configuration", Cause: err}
	}
	if client.PrivateKeyJWT != nil {
		if !assertionAttempt {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication"}
		}
		if err := s.validateJWTClient(ctx, req, clientID, client.PrivateKeyJWT); err != nil {
			return nil, err
		}
		return client, nil
	}
	if assertionAttempt {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication"}
	}
	if client.Public {
		if req.ClientSecret != "" {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication"}
		}
		return client, nil
	}

	secrets := client.Secrets
	if len(secrets) == 0 {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client secret"}
	}

	var matchFound int32
	for _, secret := range secrets {
		matchFound |= int32(subtle.ConstantTimeCompare([]byte(secret), []byte(req.ClientSecret)))
	}
	if matchFound != 1 {
		return nil, &oauth2proto.TokenError{
			ErrorCode:   oauth2proto.TokenErrorCodeInvalidClient,
			Description: "Invalid client secret",
		}
	}

	return client, nil
}

func (s *Server) validateJWTClient(ctx context.Context, req *oauth2proto.TokenRequest, clientID string, keys *jwt.VerificationKeySet) error {
	if req.ClientAssertion == "" || req.ClientAssertionType == "" {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "client_assertion and client_assertion_type are both required"}
	}
	if req.ClientAssertionType != clientjwt.AssertionType {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "unsupported client_assertion_type"}
	}
	if req.ClientSecret != "" {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "client_assertion cannot be combined with client_secret"}
	}

	if keys == nil {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication"}
	}
	verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
		ExpectedIssuer:    clientID,
		ExpectedAudiences: []string{s.tokenURL()},
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256, jwt.RS256},
		Type:              jwt.TypeJWTOrAbsent,
		RequireIssuedAt:   true,
		ClockSkew:         jwt.DefaultClockSkew,
	})
	if err != nil {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: err}
	}
	verified, err := verifier.Verify(req.ClientAssertion)
	if err != nil {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: err}
	}
	sub, err := verified.Subject()
	if err != nil || sub != clientID {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: fmt.Errorf("subject does not match client")}
	}
	jti, err := verified.JWTID()
	if err != nil || len(jti) == 0 || len(jti) > clientAssertionMaxJTI {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: fmt.Errorf("jti is required")}
	}
	iat, err := verified.IssuedAt()
	if err != nil {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: err}
	}
	exp, err := verified.ExpiresAt()
	if err != nil || !exp.After(iat) || exp.Sub(iat) > clientAssertionMaxLifetime {
		return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: fmt.Errorf("assertion lifetime is invalid")}
	}
	if err := s.config.Storage.useClientAssertion(ctx, clientID, jti, exp.Add(jwt.DefaultClockSkew)); err != nil {
		if errors.Is(err, ErrClientAssertionReplay) {
			return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidClient, Description: "Invalid client authentication", Cause: err}
		}
		return &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to record client assertion", Cause: err}
	}
	return nil
}

type unauthorizedErr interface {
	error
	Unauthorized() bool
}
