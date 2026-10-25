package discovery_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/provider"
	"lds.li/passidp/internal/oauth2as/discovery"
)

func TestConfigurationHandlerCaching(t *testing.T) {
	keys := testKeys(t, "one")
	metadata := testMetadata()
	h := newHandler(t, discovery.ConfigurationHandlerConfig{
		Metadata:         metadata,
		VerificationKeys: keys,
		MetadataMaxAge:   23 * time.Minute,
		JWKSMaxAge:       7 * time.Minute,
	})

	metadata.Issuer = "https://mutated.invalid"
	metadata.ResponseTypesSupported[0] = "mutated"

	metadataResponse := request(h, http.MethodGet, "/.well-known/openid-configuration", "")
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", metadataResponse.Code)
	}
	if got, want := metadataResponse.Header().Get("Cache-Control"), "public, max-age=1380, must-revalidate"; got != want {
		t.Fatalf("metadata cache control = %q, want %q", got, want)
	}
	if metadataResponse.Header().Get("ETag") == "" || metadataResponse.Header().Get("ETag")[0] != '"' {
		t.Fatalf("metadata ETag = %q, want quoted", metadataResponse.Header().Get("ETag"))
	}
	var served provider.OIDCProviderMetadata
	if err := jsonv2.Unmarshal(metadataResponse.Body.Bytes(), &served); err != nil {
		t.Fatal(err)
	}
	if served.Issuer != "https://issuer.example" || served.ResponseTypesSupported[0] != "code" {
		t.Fatalf("metadata was not isolated from caller mutation: %#v", served)
	}

	keysResponse := request(h, http.MethodGet, "/.well-known/jwks.json", "")
	if keysResponse.Code != http.StatusOK {
		t.Fatalf("jwks status = %d", keysResponse.Code)
	}
	if got, want := keysResponse.Header().Get("Cache-Control"), "public, max-age=420, must-revalidate"; got != want {
		t.Fatalf("jwks cache control = %q, want %q", got, want)
	}
	if got := keysResponse.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Fatalf("jwks content type = %q", got)
	}
	etag := keysResponse.Header().Get("ETag")
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag} {
		conditional := request(h, http.MethodGet, "/.well-known/jwks.json", inm)
		if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 {
			t.Fatalf("If-None-Match %q: status=%d body=%q", inm, conditional.Code, conditional.Body.String())
		}
		if conditional.Header().Get("ETag") != etag || conditional.Header().Get("Cache-Control") == "" {
			t.Fatalf("304 headers = %#v", conditional.Header())
		}
	}
	if mismatch := request(h, http.MethodGet, "/.well-known/jwks.json", `"other"`); mismatch.Code != http.StatusOK {
		t.Fatalf("mismatched ETag status = %d", mismatch.Code)
	}
	if head := request(h, http.MethodHead, "/.well-known/jwks.json", ""); head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%q", head.Code, head.Body.String())
	}
}

func TestConfigurationHandlerPreservesMetadataExtensions(t *testing.T) {
	metadata := testMetadata()
	metadata.Extensions = map[string]jsontext.Value{"vendor_feature": jsontext.Value(`{"enabled":true}`)}
	h := newHandler(t, discovery.ConfigurationHandlerConfig{Metadata: metadata, VerificationKeys: testKeys(t, "one")})
	response := request(h, http.MethodGet, "/.well-known/openid-configuration", "")
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", response.Code)
	}
	var served provider.OIDCProviderMetadata
	if err := jsonv2.Unmarshal(response.Body.Bytes(), &served); err != nil {
		t.Fatal(err)
	}
	if got := string(served.Extensions["vendor_feature"]); got != `{"enabled":true}` {
		t.Fatalf("extension = %s, want original JSON value", got)
	}
}

func TestConfigurationHandlerKeyReplacement(t *testing.T) {
	first := testKeys(t, "one")
	h := newHandler(t, discovery.ConfigurationHandlerConfig{Metadata: testMetadata(), VerificationKeys: first})
	before := request(h, http.MethodGet, "/.well-known/jwks.json", "")
	second := testKeys(t, "two")
	if err := first.Replace(second); err != nil {
		t.Fatal(err)
	}
	after := request(h, http.MethodGet, "/.well-known/jwks.json", "")
	if before.Header().Get("ETag") == after.Header().Get("ETag") || before.Body.String() == after.Body.String() {
		t.Fatal("key replacement did not immediately change JWKS representation")
	}

	bytes, err := second.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := jwt.ParseVerificationJWKS(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Replace(equivalent); err != nil {
		t.Fatal(err)
	}
	unchanged := request(h, http.MethodGet, "/.well-known/jwks.json", "")
	if unchanged.Header().Get("ETag") != after.Header().Get("ETag") {
		t.Fatal("equivalent key contents changed ETag")
	}
}

func TestConfigurationHandlerConcurrentReplacement(t *testing.T) {
	keys := testKeys(t, "one")
	h := newHandler(t, discovery.ConfigurationHandlerConfig{Metadata: testMetadata(), VerificationKeys: keys})
	keySets := []*jwt.VerificationKeySet{keys, testKeys(t, "two"), testKeys(t, "three")}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				response := request(h, http.MethodGet, "/.well-known/jwks.json", "")
				if response.Code != http.StatusOK {
					t.Errorf("jwks status = %d", response.Code)
				}
			}
		})
	}
	for _, next := range keySets {
		if err := keys.Replace(next); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestConfigurationHandlerDefaultsAndValidation(t *testing.T) {
	keys := testKeys(t, "one")
	h := newHandler(t, discovery.ConfigurationHandlerConfig{Metadata: testMetadata(), VerificationKeys: keys})
	if got := request(h, http.MethodGet, "/.well-known/openid-configuration", "").Header().Get("Cache-Control"); got != "public, max-age=3600, must-revalidate" {
		t.Fatalf("metadata defaults = %q", got)
	}
	if got := request(h, http.MethodGet, "/.well-known/jwks.json", "").Header().Get("Cache-Control"); got != "public, max-age=300, must-revalidate" {
		t.Fatalf("jwks defaults = %q", got)
	}
	for _, config := range []discovery.ConfigurationHandlerConfig{
		{Metadata: testMetadata(), VerificationKeys: keys, MetadataMaxAge: -time.Second},
		{Metadata: testMetadata(), VerificationKeys: keys, JWKSMaxAge: -time.Second},
		{Metadata: testMetadata(), VerificationKeys: keys, MetadataMaxAge: time.Second + time.Millisecond},
		{Metadata: testMetadata(), VerificationKeys: keys, JWKSMaxAge: time.Second + time.Millisecond},
		{VerificationKeys: keys},
		{Metadata: testMetadata()},
	} {
		if _, err := discovery.NewOIDCConfigurationHandler(config); err == nil {
			t.Fatal("invalid configuration unexpectedly accepted")
		}
	}
}

func testMetadata() *provider.OIDCProviderMetadata {
	return &provider.OIDCProviderMetadata{
		Issuer:                           "https://issuer.example",
		AuthorizationEndpoint:            "https://issuer.example/authorize",
		TokenEndpoint:                    "https://issuer.example/token",
		JWKSURI:                          "https://issuer.example/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		GrantTypesSupported:              []string{"authorization_code"},
	}
}

func testKeys(t *testing.T, kid string) *jwt.VerificationKeySet {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwt.NewVerificationKeySet(jwt.VerificationKey{Key: &key.PublicKey, Algorithm: jwt.ES256, KeyID: kid})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func newHandler(t *testing.T, config discovery.ConfigurationHandlerConfig) http.Handler {
	t.Helper()
	h, err := discovery.NewOIDCConfigurationHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(handler http.Handler, method, path, ifNoneMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://issuer.example"+path, strings.NewReader(""))
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
