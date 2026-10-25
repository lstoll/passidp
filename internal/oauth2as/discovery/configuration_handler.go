package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/provider"
)

const (
	DefaultMetadataMaxAge = time.Hour
	DefaultJWKSMaxAge     = 5 * time.Minute
)

var _ http.Handler = (*OIDCConfigurationHandler)(nil)

// OIDCConfigurationHandler is an http.Handler that serves the OIDC provider
// metadata endpoint and its current verification keys.
//
// It should be mounted at `GET /.well-known/openid-configuration`, and `GET
// /.well-known/jwks.json` (unless overridden)
type OIDCConfigurationHandler struct {
	metadata         representation
	verificationKeys *jwt.VerificationKeySet
	mux              *http.ServeMux
	jwksMaxAge       time.Duration
}

// ConfigurationHandlerConfig configures an OIDCConfigurationHandler.
//
// Publish a new signing key and wait for previously served JWKS responses to
// expire or revalidate before using it. Retain old verification keys until all
// tokens signed by them have expired, including any accepted clock skew. An
// ETag cannot revoke a still-fresh cached response.
type ConfigurationHandlerConfig struct {
	Metadata         *provider.OIDCProviderMetadata
	VerificationKeys *jwt.VerificationKeySet
	MetadataMaxAge   time.Duration
	JWKSMaxAge       time.Duration
}

type representation struct {
	body         []byte
	etag         string
	contentType  string
	cacheControl string
}

// DefaultCoreMetadata returns a ProviderMetadata instance with defaults
// suitable for the core package in this module. Most endpoints will need to be
// added to this.
func DefaultCoreMetadata(issuer string) *provider.OIDCProviderMetadata {
	return &provider.OIDCProviderMetadata{
		Issuer: issuer,
		ResponseTypesSupported: []string{
			"code",
			"id_token",
			"id_token token",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		GrantTypesSupported:              []string{"authorization_code"},
		CodeChallengeMethodsSupported:    []provider.CodeChallengeMethod{provider.CodeChallengeMethodS256},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
		},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"ES256", "RS256"},
		JWKSURI: issuer + "/.well-known/jwks.json",
	}
}

// NewOIDCConfigurationHandler configures and returns an OIDC configuration
// handler for the given provider metadata and stable verification key set.
//
// The handler should be configured to serve the following paths:
// GET /.well-known/openid-configuration
// GET /.well-known/jwks.json (unless overridden)
func NewOIDCConfigurationHandler(config ConfigurationHandlerConfig) (*OIDCConfigurationHandler, error) {
	if config.Metadata == nil {
		return nil, fmt.Errorf("metadata is required")
	}
	if config.VerificationKeys == nil {
		return nil, fmt.Errorf("verification keys are required")
	}
	metadataMaxAge := config.MetadataMaxAge
	if metadataMaxAge == 0 {
		metadataMaxAge = DefaultMetadataMaxAge
	}
	jwksMaxAge := config.JWKSMaxAge
	if jwksMaxAge == 0 {
		jwksMaxAge = DefaultJWKSMaxAge
	}
	if metadataMaxAge < 0 {
		return nil, fmt.Errorf("metadata max age must not be negative")
	}
	if jwksMaxAge < 0 {
		return nil, fmt.Errorf("jwks max age must not be negative")
	}
	if metadataMaxAge%time.Second != 0 {
		return nil, fmt.Errorf("metadata max age must be a whole number of seconds")
	}
	if jwksMaxAge%time.Second != 0 {
		return nil, fmt.Errorf("jwks max age must be a whole number of seconds")
	}

	metadata, err := cloneMetadata(config.Metadata)
	if err != nil {
		return nil, err
	}

	jwksPath := `/.well-known/jwks.json`
	if metadata.JWKSURI != "" {
		// Note - if it's a different host, this will fail. If that is a desired
		// use case, the metadata serving should be constructed manually.
		u, err := url.Parse(metadata.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("parsing JWKSURI %s: %w", metadata.JWKSURI, err)
		}
		jwksPath = u.Path
	} else {
		metadata.JWKSURI = metadata.Issuer + jwksPath
	}

	if err := validateMetadata(metadata); err != nil {
		return nil, err
	}

	metadataBytes, err := jsonv2.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshalling provider metadata: %w", err)
	}

	h := &OIDCConfigurationHandler{
		metadata:         newRepresentation(metadataBytes, "application/json", metadataMaxAge),
		verificationKeys: config.VerificationKeys,
		mux:              http.NewServeMux(),
		jwksMaxAge:       jwksMaxAge,
	}

	h.mux.HandleFunc("GET /.well-known/openid-configuration", h.serveConfig)
	h.mux.HandleFunc("GET "+jwksPath, h.serveKeys)

	return h, nil
}

func (h *OIDCConfigurationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *OIDCConfigurationHandler) serveConfig(w http.ResponseWriter, req *http.Request) {
	serveRepresentation(w, req, h.metadata)
}

func (h *OIDCConfigurationHandler) serveKeys(w http.ResponseWriter, req *http.Request) {
	jwks, err := h.verificationKeys.JWKS()
	if err != nil {
		slog.ErrorContext(req.Context(), "getting jwks", "err", err.Error())
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	serveRepresentation(w, req, newRepresentation(jwks, "application/jwk-set+json", h.jwksMaxAge))
}

func newRepresentation(body []byte, contentType string, maxAge time.Duration) representation {
	sum := sha256.Sum256(body)
	return representation{
		body:         body,
		etag:         `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`,
		contentType:  contentType,
		cacheControl: "public, max-age=" + strconv.FormatInt(int64(maxAge/time.Second), 10) + ", must-revalidate",
	}
}

func serveRepresentation(w http.ResponseWriter, req *http.Request, rep representation) {
	w.Header().Set("Content-Type", rep.contentType)
	w.Header().Set("Cache-Control", rep.cacheControl)
	w.Header().Set("ETag", rep.etag)
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(rep.body))
}

func cloneMetadata(metadata *provider.OIDCProviderMetadata) (*provider.OIDCProviderMetadata, error) {
	encoded, err := jsonv2.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("cloning provider metadata: %w", err)
	}
	var clone provider.OIDCProviderMetadata
	if err := jsonv2.Unmarshal(encoded, &clone); err != nil {
		return nil, fmt.Errorf("cloning provider metadata: %w", err)
	}
	return &clone, nil
}

func validateMetadata(p *provider.OIDCProviderMetadata) error {
	var errs []string

	aestr := func(val, e string) {
		if val == "" {
			errs = append(errs, e)
		}
	}

	aessl := func(val []string, e string) {
		if len(val) == 0 {
			errs = append(errs, e)
		}
	}

	aestr(p.Issuer, "Issuer is required")
	aestr(p.AuthorizationEndpoint, "AuthorizationEndpoint is required")
	aestr(p.JWKSURI, "JWKSURI is required")
	aessl(p.ResponseTypesSupported, "ResponseTypes supported is required")
	aessl(p.SubjectTypesSupported, "Subject Identifier Types are required")
	aessl(p.IDTokenSigningAlgValuesSupported, "IDTokenSigningAlgValuesSupported are required")

	if p.TokenEndpoint == "" {
		if len(p.GrantTypesSupported) != 1 || p.GrantTypesSupported[0] != "implicit" {
			errs = append(errs, "TokenEndpoint is required when we're not implicit-only")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid provider metadata: %s", strings.Join(errs, ", "))
	}
	return nil
}
