package oauth2proto

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseToken(t *testing.T) {
	for _, tc := range []struct {
		Name        string
		Req         func() *http.Request
		WantErr     bool
		WantErrCode TokenErrorCode
		Want        *TokenRequest
	}{
		{
			Name: "Bad method",
			Req: func() *http.Request {
				return httptest.NewRequest("HEAD", "/", nil)
			},
			WantErr: true,
		},
		{
			Name: "Reject query parameters",
			Req: func() *http.Request {
				req := queryReq(map[string]string{"grant_type": "authorization_code"})()
				req.URL.RawQuery = "code=acode&redirect_uri=https%3A%2F%2Fredirect"
				return req
			},
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidRequest,
		},
		{
			Name: "Reject repeated parameters",
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":         "acode",
					"redirect_uri": "https://redirect",
					"grant_type":   "authorization_code",
				})()
				req.Body = io.NopCloser(strings.NewReader("code=acode&code=another&redirect_uri=https%3A%2F%2Fredirect&grant_type=authorization_code"))
				return req
			},
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidRequest,
		},
		{
			Name: "Reject non-form content type",
			Req: func() *http.Request {
				req := queryReq(map[string]string{"grant_type": "refresh_token", "refresh_token": "token"})()
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidRequest,
		},
		{
			Name: "Reject body credentials with basic authentication",
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":          "acode",
					"redirect_uri":  "https://redirect",
					"grant_type":    "authorization_code",
					"client_id":     "body-client",
					"client_secret": "body-secret",
				})()
				req.SetBasicAuth("basic-client", "basic-secret")
				return req
			},
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidRequest,
		},
		{
			Name: "Reject multiple authorization headers",
			Req: func() *http.Request {
				req := queryReq(map[string]string{"grant_type": "refresh_token", "refresh_token": "token"})()
				req.Header.Add("Authorization", "Basic Y2xpZW50OnNlY3JldA==")
				req.Header.Add("Authorization", "Basic Y2xpZW50OnNlY3JldA==")
				return req
			},
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidClient,
		},
		{
			Name: "Reject malformed authorization instead of falling back to body credentials",
			Req: func() *http.Request {
				req := queryReq(map[string]string{"grant_type": "refresh_token", "refresh_token": "token", "client_id": "client", "client_secret": "secret"})()
				req.Header.Set("Authorization", "Bearer token")
				return req
			},
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidClient,
		},
		{
			Name: "Good query",
			Req: queryReq(map[string]string{
				"code":          "acode",
				"redirect_uri":  "https://redirect",
				"client_id":     "client",
				"client_secret": "secret",
				"grant_type":    "authorization_code",
			}),
			Want: &TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			Name: "Basic auth creds",
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":         "acode",
					"redirect_uri": "https://redirect",
					"grant_type":   "authorization_code",
				})()
				req.SetBasicAuth("clientuser", "clientsecret")
				return req
			},
			Want: &TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "clientuser",
				ClientSecret: "clientsecret",
			},
		},
		{
			Name: "Invalid grant type",
			Req: queryReq(map[string]string{
				"code":          "acode",
				"redirect_uri":  "https://redirect",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidGrant,
		},
		{
			Name: "Valid refresh request succeeds",
			Req: queryReq(map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": "refreshtok",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			Want: &TokenRequest{
				GrantType:    GrantTypeRefreshToken,
				RefreshToken: "refreshtok",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			Name: "Refresh grant requires refresh token",
			Req: queryReq(map[string]string{
				"grant_type":    "refresh_token",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			WantErr:     true,
			WantErrCode: TokenErrorCodeInvalidRequest,
		},
		{
			Name: "JWT client assertion",
			Req: queryReq(map[string]string{
				"code":                  "acode",
				"redirect_uri":          "https://redirect",
				"client_id":             "client",
				"grant_type":            "authorization_code",
				"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				"client_assertion":      "header.payload.sig",
			}),
			Want: &TokenRequest{
				GrantType:           GrantTypeAuthorizationCode,
				Code:                "acode",
				RedirectURI:         "https://redirect",
				ClientID:            "client",
				ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				ClientAssertion:     "header.payload.sig",
			},
		},
		{
			Name: "URL-encoded basic auth special characters",
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":         "acode",
					"redirect_uri": "https://redirect",
					"grant_type":   "authorization_code",
				})()

				req.SetBasicAuth(url.QueryEscape("cl#i$nt"), url.QueryEscape("sec=ret%"))
				return req
			},
			Want: &TokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "cl#i$nt",
				ClientSecret: "sec=ret%",
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := ParseTokenRequest(tc.Req())
			if tc.WantErr && err == nil {
				t.Fatal("want err, got none")
			}
			if !tc.WantErr && err != nil {
				t.Fatalf("want no error, got: %v", err)
			}
			if tc.WantErrCode != TokenErrorCode("") {
				terr, ok := err.(*TokenError)
				if !ok {
					t.Fatalf("want tokenError, got: %v of type %T", err, err)
				}
				if tc.WantErrCode != terr.ErrorCode {
					t.Fatalf("want err code %s, got: %s", tc.WantErrCode, terr.ErrorCode)
				}
			}

			if diff := cmp.Diff(tc.Want, resp); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func queryReq(query map[string]string) func() *http.Request {
	f := url.Values{}
	for k, v := range query {
		f[k] = []string{v}
	}

	return func() *http.Request {
		req := httptest.NewRequest("POST", "https://token", strings.NewReader(f.Encode()))
		req.Header.Add("content-type", "application/x-www-form-urlencoded")
		return req
	}
}

func TestWriteTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Resp *TokenResponse
		Want map[string]any
	}{
		{
			Name: "valid response",
			Resp: &TokenResponse{
				AccessToken:  "access",
				TokenType:    "Bearer",
				ExpiresIn:    1 * time.Minute,
				RefreshToken: "refresh",
				Scopes:       []string{"openid"},
				ExtraParams: map[string]any{
					"id_token": "beer",
				},
			},
			Want: map[string]any{
				"access_token":  "access",
				"expires_in":    float64(60),
				"id_token":      "beer",
				"refresh_token": "refresh",
				"scope":         "openid",
				"token_type":    "Bearer",
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			w := httptest.NewRecorder()

			_ = WriteTokenResponse(w, tc.Resp)

			if w.Result().StatusCode != 200 {
				t.Errorf("want OK status, got %d", w.Result().StatusCode)
			}

			got := map[string]any{}
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.Want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}
