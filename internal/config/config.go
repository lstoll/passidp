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

	"github.com/tailscale/hujson"
)

type Config struct {
	// Issuer is the issuer URL for this config.
	Issuer string `json:"issuer"`
	// ParsedIssuer is the parsed issuer URL, this happens at load time.
	ParsedIssuer *url.URL `json:"-"`
	// Clients is a list of fixed clients for this issuer.
	Clients []Client `json:"clients,omitempty"`
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
