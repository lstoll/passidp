package oidcsvr

import (
	"testing"
	"time"
	"uuid"

	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oauth2as"
)

func TestTokenHandlerUsesAuthenticatedClient(t *testing.T) {
	userID := uuid.NewV4()
	h := &Handlers{Config: &config.Config{Users: config.Users{{ID: userID, Email: "user@example.com"}}, DPoPRefreshValidity: config.JSONDuration(time.Hour)}}
	for _, bound := range []bool{false, true} {
		client := &oauth2as.Client{ID: "client", TokenValidity: time.Minute, RefreshValidity: 2 * time.Minute, DPoPRefreshValidity: 3 * time.Minute}
		before := time.Now()
		response, err := h.TokenHandler(t.Context(), &oauth2as.TokenRequest{UserID: userID.String(), ClientID: client.ID, Client: client, DPoPBound: bound})
		if err != nil {
			t.Fatal(err)
		}
		refreshValidity := client.RefreshValidity
		if bound {
			refreshValidity = client.DPoPRefreshValidity
		}
		if response.RefreshTokenValidUntil.Before(before.Add(refreshValidity)) || response.RefreshTokenValidUntil.After(time.Now().Add(refreshValidity)) {
			t.Fatal("client refresh validity was not applied")
		}
		if response.AccessTokenExpiry.Before(before.Add(client.TokenValidity)) || response.AccessTokenExpiry.After(time.Now().Add(client.TokenValidity)) {
			t.Fatal("client token validity was not applied")
		}
	}
	if _, err := h.TokenHandler(t.Context(), &oauth2as.TokenRequest{UserID: userID.String(), ClientID: "client"}); err == nil {
		t.Fatal("missing authenticated client accepted")
	}
}
