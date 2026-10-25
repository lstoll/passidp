package oauth2as

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"
	"time"
)

func TestBuildTokenClaims(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	thumbprint := "dpop-thumbprint"
	additionalState, err := json.Marshal(storedAdditionalState{DPoPThumbprint: &thumbprint})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		config: Config{
			Issuer:              "https://issuer.example",
			IDTokenValidity:     time.Hour,
			AccessTokenValidity: 30 * time.Minute,
		},
		now: func() time.Time { return now },
	}
	grant := &storedGrant{
		UserID:          "stored-subject",
		ClientID:        "client-id",
		GrantedScopes:   []string{"openid", "profile"},
		GrantedAt:       now.Add(-time.Minute),
		AuthenticatedAt: now.Add(-30 * time.Second),
		ACR:             "urn:example:mfa",
		AMR:             []string{"pwd", "otp"},
		AdditionalState: additionalState,
		Request:         &AuthRequest{Nonce: "request-nonce"},
	}
	idAdditional := map[string]any{"groups": []string{"engineering"}}
	accessAdditional := map[string]any{"employee_type": "employee"}
	response := &TokenResponse{
		IDTokenClaims: &IDTokenClaims{
			Subject:    "pairwise-subject",
			Additional: idAdditional,
		},
		AccessTokenClaims: &AccessTokenClaims{
			Subject:    "api-subject",
			Audiences:  []string{"https://api.example"},
			Scopes:     []string{"records:read"},
			Additional: accessAdditional,
		},
	}

	idInput, err := server.buildIDClaims(grant, response)
	if err != nil {
		t.Fatal(err)
	}
	if idInput.Type != "" {
		t.Fatalf("ID token typ must be absent, got %q", idInput.Type)
	}
	idPayload, err := jsonv2.Marshal(idInput.Claims)
	if err != nil {
		t.Fatal(err)
	}
	idClaims := decodeClaims(t, idPayload)
	for name, want := range map[string]string{
		"iss":   "https://issuer.example",
		"sub":   "pairwise-subject",
		"aud":   "client-id",
		"nonce": "request-nonce",
		"acr":   "urn:example:mfa",
	} {
		if got := idClaims[name]; got != want {
			t.Errorf("ID claim %s: want %q, got %#v", name, want, got)
		}
	}
	if idClaims["auth_time"] != float64(grant.AuthenticatedAt.Unix()) {
		t.Errorf("unexpected auth_time: %#v", idClaims["auth_time"])
	}
	amr, ok := idClaims["amr"].([]any)
	if !ok || len(amr) != 2 || amr[0] != "pwd" || amr[1] != "otp" {
		t.Errorf("unexpected amr: %#v", idClaims["amr"])
	}

	accessInput, expiresAt, err := server.buildAccessTokenClaims("grant-id", grant, response)
	if err != nil {
		t.Fatal(err)
	}
	if accessInput.Type != "at+jwt" {
		t.Fatalf("access token typ: want at+jwt, got %q", accessInput.Type)
	}
	if want := now.Add(30 * time.Minute); !expiresAt.Equal(want) {
		t.Fatalf("access expiry: want %v, got %v", want, expiresAt)
	}
	accessPayload, err := jsonv2.Marshal(accessInput.Claims)
	if err != nil {
		t.Fatal(err)
	}
	accessClaims := decodeClaims(t, accessPayload)
	if accessClaims["sub"] != "api-subject" || accessClaims["client_id"] != "client-id" || accessClaims["grid"] != "grant-id" {
		t.Fatalf("unexpected access token claims: %v", accessClaims)
	}
	if accessClaims["scope"] != "records:read" || accessClaims["employee_type"] != "employee" {
		t.Fatalf("unexpected application access claims: %v", accessClaims)
	}
	cnf, ok := accessClaims["cnf"].(map[string]any)
	if !ok || cnf["jkt"] != thumbprint {
		t.Fatalf("unexpected cnf claim: %#v", accessClaims["cnf"])
	}
	if _, ok := idAdditional["iss"]; ok {
		t.Fatal("ID-token Additional map was mutated")
	}
	if _, ok := accessAdditional["scope"]; ok {
		t.Fatal("access-token Additional map was mutated")
	}
}

func TestBuildTokenClaimsRejectsReservedAdditionalClaims(t *testing.T) {
	server := &Server{
		config: Config{Issuer: "https://issuer.example", IDTokenValidity: time.Hour, AccessTokenValidity: time.Hour},
		now:    time.Now,
	}
	grant := &storedGrant{UserID: "subject", ClientID: "client", GrantedAt: time.Now()}

	_, err := server.buildIDClaims(grant, &TokenResponse{
		IDTokenClaims: &IDTokenClaims{Additional: map[string]any{"iss": "attacker"}},
	})
	if err == nil || !strings.Contains(err.Error(), `claim "iss" is managed`) {
		t.Fatalf("unexpected ID-token reserved-claim error: %v", err)
	}
	_, _, err = server.buildAccessTokenClaims("grant", grant, &TokenResponse{
		AccessTokenClaims: &AccessTokenClaims{Additional: map[string]any{"cnf": map[string]any{}}},
	})
	if err == nil || !strings.Contains(err.Error(), `claim "cnf" is managed`) {
		t.Fatalf("unexpected access-token reserved-claim error: %v", err)
	}
}

func decodeClaims(t testing.TB, payload []byte) map[string]any {
	t.Helper()
	var claims map[string]any
	if err := jsonv2.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
