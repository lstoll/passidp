package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"
	"github.com/tailscale/hujson"
	"golang.org/x/time/rate"
	"sigs.k8s.io/yaml"
)

type Config struct {
	// Issuer is the issuer URL for this config.
	Issuer string `json:"issuer"`
	// ParsedIssuer is the parsed issuer URL, this happens at load time.
	ParsedIssuer *url.URL `json:"-"`
	// Clients is a list of fixed clients for this issuer.
	Clients []Client `json:"clients,omitempty"`
	// Users is a list of users for this issuer.
	Users Users `json:"users,omitempty"`
	// SessionDuration is the duration a web login session is valid for.
	// Defaults to 1h.
	SessionDuration JSONDuration `json:"session_duration,omitempty"`

	// TokenValidity is the duration ID and access tokens are valid for.
	// Defaults to 1h.
	TokenValidity JSONDuration `json:"token_validity,omitempty"`

	// RefreshValidity is the duration a refresh token is valid for. Defaults to 24h.
	RefreshValidity JSONDuration `json:"refresh_validity,omitempty"`

	// DPoPRefreshValidity is the duration a DPoP refresh token is valid for. Defaults to 24h.
	DPoPRefreshValidity JSONDuration `json:"dpop_refresh_validity,omitempty"`

	// GrantValidity is the duration grants are valid for. Defaults to 24h.
	GrantValidity JSONDuration `json:"grant_validity,omitempty"`

	// RefreshTokenRotationGracePeriod is the grace period for refreshing
	// refresh tokens, during this time the old token can still be used to
	// account for network issues etc.. Defaults to 1 minute.
	RefreshTokenRotationGracePeriod JSONDuration `json:"refresh_token_rotation_grace_period,omitempty"`

	// Serving contains configuration for serving the OIDC server.
	Serving ServingConfig `json:"serving"`
}

// ServingConfig contains configuration for serving the OIDC server.
type ServingConfig struct {
	// AuthLimitRate is the rate limit for authentication endpoints in requests per second. Defaults to 0.5.
	AuthLimitRate rate.Limit `json:"authLimitRate,omitempty"`
	// AuthLimitBucket is the burst size for authentication endpoints. Defaults to 4.
	AuthLimitBucket int `json:"authLimitBucket,omitempty"`
}

// ParseConfig parses the config from the given file, expanding environment
// variables and validating the config.
func ParseConfig(cfgFile kong.NamedFileContentFlag) (*Config, error) {
	scb := []byte(os.Expand(string(cfgFile.Contents), getenvWithDefault))

	var err error
	if slices.Contains([]string{".yaml", ".yml"}, filepath.Ext(cfgFile.Filename)) {
		scb, err = yaml.YAMLToJSON(scb)
	} else {
		scb, err = hujson.Standardize(scb)
	}
	if err != nil {
		return nil, fmt.Errorf("standardize config: %w", err)
	}

	var c Config
	dec := json.NewDecoder(bytes.NewReader(scb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if err := c.SetDefaults(); err != nil {
		return nil, fmt.Errorf("set defaults: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &c, nil
}

func (c *Config) SetDefaults() error {
	for i := range c.Clients {
		cl := &c.Clients[i]
		if len(cl.RequiredGroups) > 0 {
			cl.AuthorizationPolicy = calculateAuthPolicyForClient(cl)
		}
	}

	if c.SessionDuration == 0 {
		c.SessionDuration = JSONDuration(1 * time.Hour)
	}
	if c.TokenValidity == 0 {
		c.TokenValidity = JSONDuration(1 * time.Hour)
	}
	if c.RefreshValidity == 0 {
		c.RefreshValidity = JSONDuration(24 * time.Hour)
	}
	if c.DPoPRefreshValidity == 0 {
		c.DPoPRefreshValidity = JSONDuration(24 * time.Hour)
	}
	if c.GrantValidity == 0 {
		c.GrantValidity = JSONDuration(24 * time.Hour)
	}
	if c.RefreshTokenRotationGracePeriod == 0 {
		c.RefreshTokenRotationGracePeriod = JSONDuration(1 * time.Minute)
	}
	if c.Serving.AuthLimitRate == 0 {
		c.Serving.AuthLimitRate = rate.Limit(0.5)
	}
	if c.Serving.AuthLimitBucket == 0 {
		c.Serving.AuthLimitBucket = 4
	}
	return nil
}

func (c *Config) Validate() error {
	var validErr error

	if c.Issuer == "" {
		validErr = errors.Join(validErr, fmt.Errorf("issuer is required"))
	} else {
		u, err := url.Parse(c.Issuer)
		if err != nil {
			validErr = errors.Join(validErr, fmt.Errorf("issuer %s is not a valid URL: %w", c.Issuer, err))
		}
		c.ParsedIssuer = u
	}

	for _, cl := range c.Clients {
		if cl.ID == "" {
			validErr = errors.Join(validErr, fmt.Errorf("client %s missing ID", cl.ID))
		}
		if len(cl.RequiredGroups) > 0 && cl.AuthorizationPolicy != calculateAuthPolicyForClient(&cl) {
			validErr = errors.Join(validErr, fmt.Errorf("client %s cannot have both requiredGroups and authorizationPolicy", cl.ID))
		}
		if len(cl.Secrets) == 0 && !cl.Public {
			validErr = errors.Join(validErr, fmt.Errorf("non-public client %s missing client secrets", cl.ID))
		}
		if len(cl.RedirectURLs) == 0 {
			validErr = errors.Join(validErr, fmt.Errorf("client %s missing redirect URLs", cl.ID))
		}
	}

	for _, u := range c.Users {
		if u.ID == uuid.Nil {
			validErr = errors.Join(validErr, fmt.Errorf("user %s missing ID", u.ID))
		}
		if u.Email == "" {
			validErr = errors.Join(validErr, fmt.Errorf("user %s missing email", u.ID))
		}
		if u.FullName == "" {
			validErr = errors.Join(validErr, fmt.Errorf("user %s missing full name", u.ID))
		}
		if u.WebauthnHandle == uuid.Nil {
			validErr = errors.Join(validErr, fmt.Errorf("user %s missing webauthn handle", u.ID))
		}
		if u.WebauthnHandle == u.ID {
			validErr = errors.Join(validErr, fmt.Errorf("user %s webauthn handle must be a different UUID than the user ID", u.ID))
		}
	}

	if c.Serving.AuthLimitRate < 0 {
		validErr = errors.Join(validErr, fmt.Errorf("authLimitRate must be non-negative, got: %f", float64(c.Serving.AuthLimitRate)))
	}
	if c.Serving.AuthLimitBucket < 0 {
		validErr = errors.Join(validErr, fmt.Errorf("authLimitBucket must be non-negative, got: %d", c.Serving.AuthLimitBucket))
	}

	return validErr
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

func calculateAuthPolicyForClient(cl *Client) string {
	if len(cl.RequiredGroups) > 0 {
		// Construct a CEL expression that checks if any of the user's groups are in the required list
		// user.groups.exists(g, g in ['group1', 'group2'])
		return fmt.Sprintf(
			"user.groups.exists(g, g in ['%s'])",
			strings.Join(cl.RequiredGroups, "', '"),
		)
	}
	return cl.AuthorizationPolicy
}
