package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tailscale/hujson"
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
	// SessionDuration is the duration a session is valid for. Defaults to 1h.
	SessionDuration string `json:"session_duration,omitempty"`
	// ParsedSessionDuration is the parsed session duration.
	ParsedSessionDuration time.Duration `json:"-"`

	// TokenValidity is the duration a token is valid for. Defaults to 1h.
	TokenValidity string `json:"token_validity,omitempty"`
	// ParsedTokenValidity is the parsed token validity.
	ParsedTokenValidity time.Duration `json:"-"`

	// RefreshValidity is the duration a refresh token is valid for. Defaults to 24h.
	RefreshValidity string `json:"refresh_validity,omitempty"`
	// ParsedRefreshValidity is the parsed refresh validity.
	ParsedRefreshValidity time.Duration `json:"-"`

	// DPoPRefreshValidity is the duration a DPoP refresh token is valid for. Defaults to 24h.
	DPoPRefreshValidity string `json:"dpop_refresh_validity,omitempty"`
	// ParsedDPoPRefreshValidity is the parsed DPoP refresh validity.
	ParsedDPoPRefreshValidity time.Duration `json:"-"`
}

// ParseConfig parses the config from the given file, expanding environment
// variables and validating the config.
func ParseConfig(file []byte) (*Config, error) {
	scb := []byte(os.Expand(string(file), getenvWithDefault))
	scb, err := hujson.Standardize(scb)
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
	if c.SessionDuration == "" {
		c.SessionDuration = "1h"
	}
	if c.TokenValidity == "" {
		c.TokenValidity = "1h"
	}
	if c.RefreshValidity == "" {
		c.RefreshValidity = "24h"
	}
	if c.DPoPRefreshValidity == "" {
		c.DPoPRefreshValidity = "24h"
	}
	return nil
}

func (c *Config) Validate() error {
	var validErr error

	if c.SessionDuration != "" {
		d, err := time.ParseDuration(c.SessionDuration)
		if err != nil {
			validErr = errors.Join(validErr, fmt.Errorf("invalid session duration: %w", err))
		}
		c.ParsedSessionDuration = d
	}

	if c.TokenValidity != "" {
		d, err := time.ParseDuration(c.TokenValidity)
		if err != nil {
			validErr = errors.Join(validErr, fmt.Errorf("invalid token validity: %w", err))
		}
		c.ParsedTokenValidity = d
	}

	if c.RefreshValidity != "" {
		d, err := time.ParseDuration(c.RefreshValidity)
		if err != nil {
			validErr = errors.Join(validErr, fmt.Errorf("invalid refresh validity: %w", err))
		}
		c.ParsedRefreshValidity = d
	}

	if c.DPoPRefreshValidity != "" {
		d, err := time.ParseDuration(c.DPoPRefreshValidity)
		if err != nil {
			validErr = errors.Join(validErr, fmt.Errorf("invalid dpop refresh validity: %w", err))
		}
		c.ParsedDPoPRefreshValidity = d
	}

	if c.Issuer == "" {
		validErr = errors.Join(validErr, fmt.Errorf("issuer is required"))
	} else {
		u, err := url.Parse(c.Issuer)
		if err != nil {
			validErr = errors.Join(validErr, fmt.Errorf("issuer %s is not a valid URL: %w", c.Issuer, err))
		}
		c.ParsedIssuer = u
	}

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
			c.Clients[ci].ParsedTokenValidity = &tokenValidity
		}
		if cl.RefreshValidity != "" {
			refreshValidity, err := time.ParseDuration(cl.RefreshValidity)
			if err != nil {
				validErr = errors.Join(validErr, fmt.Errorf("client %s invalid refresh validity: %w", cl.ID, err))
			}
			c.Clients[ci].ParsedRefreshValidity = &refreshValidity
		}
		if cl.DPoPRefreshValidity != "" {
			dpopRefreshValidity, err := time.ParseDuration(cl.DPoPRefreshValidity)
			if err != nil {
				validErr = errors.Join(validErr, fmt.Errorf("client %s invalid dpop refresh validity: %w", cl.ID, err))
			}
			c.Clients[ci].ParsedDPoPRefreshValidity = &dpopRefreshValidity
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
