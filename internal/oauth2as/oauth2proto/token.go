package oauth2proto

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

type TokenRequest struct {
	GrantType    GrantType
	Code         string
	RefreshToken string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	// CodeVerifier is the PKCE code verifier, if it was submitted with this
	// request.
	CodeVerifier string
	// ClientAssertion is a JWT used for private_key_jwt client authentication.
	ClientAssertion string
	// ClientAssertionType is the assertion type. It must be
	// urn:ietf:params:oauth:client-assertion-type:jwt-bearer when
	// ClientAssertion is set.
	ClientAssertionType string
}

// ParseTokenRequest parses the information from a request for an access token.
//
// https://tools.ietf.org/html/rfc6749#section-4.1.3
func ParseTokenRequest(req *http.Request) (*TokenRequest, error) {
	if req.Method != http.MethodPost {
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "method must be POST"}
	}

	contentType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "content type must be application/x-www-form-urlencoded"}
	}
	if req.URL.RawQuery != "" {
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "query parameters are not allowed"}
	}
	if err := req.ParseForm(); err != nil {
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "invalid form encoding"}
	}
	for parameter, values := range req.PostForm {
		if len(values) > 1 {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: fmt.Sprintf("%s must not be repeated", parameter)}
		}
	}

	tr := &TokenRequest{
		RedirectURI:         req.PostForm.Get("redirect_uri"),
		Code:                req.PostForm.Get("code"),
		RefreshToken:        req.PostForm.Get("refresh_token"),
		CodeVerifier:        req.PostForm.Get("code_verifier"),
		ClientAssertion:     req.PostForm.Get("client_assertion"),
		ClientAssertionType: req.PostForm.Get("client_assertion_type"),
	}

	// Auth the request. Exactly one authentication method is permitted.
	// https://tools.ietf.org/html/rfc6749#section-2.3
	authorization := req.Header.Values("Authorization")
	if len(authorization) > 1 {
		return nil, invalidClientAuthentication("multiple Authorization headers")
	}
	cid, cs, isBasic := req.BasicAuth()
	if len(authorization) == 1 && !isBasic {
		return nil, invalidClientAuthentication("malformed HTTP Basic authentication")
	}
	if isBasic {
		if _, bodyClientID := req.PostForm["client_id"]; bodyClientID {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "client_id must not be sent with HTTP Basic authentication"}
		}
		if _, bodyClientSecret := req.PostForm["client_secret"]; bodyClientSecret {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "client_secret must not be sent with HTTP Basic authentication"}
		}

		tr.ClientID, err = url.QueryUnescape(cid)
		if err != nil {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "invalid encoding for client id"}
		}
		tr.ClientSecret, err = url.QueryUnescape(cs)
		if err != nil {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "invalid encoding for client secret"}
		}

	} else {
		tr.ClientID = req.PostForm.Get("client_id")
		tr.ClientSecret = req.PostForm.Get("client_secret")
	}

	switch req.PostForm.Get("grant_type") {
	case string(GrantTypeAuthorizationCode):
		if tr.Code == "" {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "code is required for authorization_code grant"}
		}
		if tr.RedirectURI == "" {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "redirect_uri is required for authorization_code grant"}
		}
		tr.GrantType = GrantTypeAuthorizationCode

	case string(GrantTypeRefreshToken):
		// https://tools.ietf.org/html/rfc6749#section-6
		if tr.RefreshToken == "" {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "refresh_token is required for refresh grant"}
		}
		tr.GrantType = GrantTypeRefreshToken

	default:
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidGrant, Description: fmt.Sprintf("grant_type must be %s", GrantTypeAuthorizationCode)}
	}

	return tr, nil
}

func invalidClientAuthentication(description string) *TokenError {
	return &TokenError{
		ErrorCode:       TokenErrorCodeInvalidClient,
		Description:     description,
		WWWAuthenticate: `Basic realm="token"`,
	}
}

// TokenResponse ref: https://tools.ietf.org/html/rfc6749#section-5.1
//
// this does eventually end up as JSON, but because of how we want to handle the
// extra params bit we don't tag this struct
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    time.Duration
	RefreshToken string
	Scopes       []string
	ExtraParams  map[string]any
}

// WriteTokenResponse sends a response for the token endpoint.
//
// https://tools.ietf.org/html/rfc6749#section-5.1
func WriteTokenResponse(w http.ResponseWriter, resp *TokenResponse) error {
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")

	respJSON := resp.ExtraParams
	if respJSON == nil {
		respJSON = make(map[string]any)
	}

	respJSON["access_token"] = resp.AccessToken
	respJSON["token_type"] = resp.TokenType

	if resp.ExpiresIn != 0 {
		respJSON["expires_in"] = int(resp.ExpiresIn.Seconds())
	}
	if resp.RefreshToken != "" {
		respJSON["refresh_token"] = resp.RefreshToken
	}
	if resp.Scopes != nil {
		respJSON["scope"] = strings.Join(resp.Scopes, " ")
	}

	if err := json.NewEncoder(w).Encode(respJSON); err != nil {
		return fmt.Errorf("failed to write token response json body: %w", err)
	}

	return nil
}
