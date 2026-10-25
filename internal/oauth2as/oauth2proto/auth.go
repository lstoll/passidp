package oauth2proto

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ResponseType string

const (
	ResponseTypeCode     ResponseType = "code"
	ResponseTypeImplicit ResponseType = "token"

	CodeChallengeMethodS256 = "S256"
)

type AuthRequest struct {
	ClientID string
	// RedirectURI the client specified. This is an OPTIONAL field, if not
	// passed will be set to the zero value
	RedirectURI  string
	State        string
	Scopes       []string
	ResponseType ResponseType
	// CodeChallenge is the PKCE code challenge. If it is provided, it will be
	// S256 format.
	CodeChallenge string
	// Nonce is the OIDC nonce value from the authorization request.
	Nonce string
	// MaxAge is the OIDC max_age parameter. Nil means the parameter was omitted.
	// A pointer to 0 means re-authentication is required.
	MaxAge *int

	// Raw is the full, unprocessed set of values passed to this request.
	Raw url.Values
}

// ParseAuthRequest can be used to process an oauth2 authentication request,
// returning information about it. It can handle both the code and implicit auth
// types. If an error is returned, it should be passed to the user via
// writeError. Parameters must not be repeated. POST requests must send
// parameters in the form body only.
//
// https://tools.ietf.org/html/rfc6749#section-4.1.1
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func ParseAuthRequest(req *http.Request) (authReq *AuthRequest, err error) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return nil, &HTTPError{Code: http.StatusBadRequest, Message: "method must be POST or GET"}
	}

	values, err := parseAuthRequestValues(req)
	if err != nil {
		return nil, err
	}

	rts := values.Get("response_type")
	cid := values.Get("client_id")
	ruri := values.Get("redirect_uri")
	scope := values.Get("scope")
	state := values.Get("state")
	codeChallenge := values.Get("code_challenge")
	codeChallengeMethod := values.Get("code_challenge_method")
	nonce := values.Get("nonce")
	maxAgeRaw := values.Get("max_age")

	var rt ResponseType
	switch rts {
	case string(ResponseTypeCode):
		rt = ResponseTypeCode
	case string(ResponseTypeImplicit):
		rt = ResponseTypeImplicit
	default:
		return nil, &AuthError{
			State:       state,
			Code:        AuthErrorCodeInvalidRequest,
			Description: `response_type must be "code" or "token"`,
		}
	}

	if cid == "" {
		return nil, &AuthError{
			State:       state,
			Code:        AuthErrorCodeInvalidRequest,
			Description: "client_id must be specified",
		}
	}

	if codeChallenge != "" && codeChallengeMethod != CodeChallengeMethodS256 {
		return nil, &AuthError{
			State:       state,
			Code:        AuthErrorCodeInvalidRequest,
			Description: fmt.Sprintf(`only code_challenge type "%s" supported`, CodeChallengeMethodS256),
		}
	}

	var scopes []string
	trimmedScope := strings.TrimSpace(scope)
	if trimmedScope != "" {
		scopes = strings.Split(trimmedScope, " ")
	}

	var maxAge *int
	if _, hasMaxAge := values["max_age"]; hasMaxAge {
		ma, err := strconv.Atoi(maxAgeRaw)
		if err != nil || ma < 0 {
			return nil, &AuthError{
				State:       state,
				Code:        AuthErrorCodeInvalidRequest,
				Description: "max_age must be a non-negative integer",
			}
		}
		maxAge = &ma
	}

	return &AuthRequest{
		ClientID:      cid,
		RedirectURI:   ruri,
		State:         state,
		Scopes:        scopes,
		ResponseType:  rt,
		Raw:           values,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		MaxAge:        maxAge,
	}, nil
}

func parseAuthRequestValues(req *http.Request) (url.Values, error) {
	if req.Method == http.MethodGet {
		values, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return nil, &AuthError{Code: AuthErrorCodeInvalidRequest, Description: "invalid query encoding"}
		}
		if err := rejectRepeatedParams(values); err != nil {
			return nil, err
		}
		return values, nil
	}

	contentType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		return nil, &AuthError{Code: AuthErrorCodeInvalidRequest, Description: "content type must be application/x-www-form-urlencoded"}
	}
	if req.URL.RawQuery != "" {
		return nil, &AuthError{Code: AuthErrorCodeInvalidRequest, Description: "query parameters are not allowed"}
	}
	if err := req.ParseForm(); err != nil {
		return nil, &AuthError{Code: AuthErrorCodeInvalidRequest, Description: "invalid form encoding"}
	}
	if err := rejectRepeatedParams(req.PostForm); err != nil {
		return nil, err
	}
	return req.PostForm, nil
}

func rejectRepeatedParams(values url.Values) error {
	for parameter, parameterValues := range values {
		if len(parameterValues) > 1 {
			return &AuthError{
				Code:        AuthErrorCodeInvalidRequest,
				Description: fmt.Sprintf("%s must not be repeated", parameter),
			}
		}
	}
	return nil
}

type CodeAuthResponse struct {
	RedirectURI *url.URL
	State       string
	Code        string
}

// ToRedirectURI builds a redirect URI to direct the user to for this response.
func (c *CodeAuthResponse) ToRedirectURI() *url.URL {
	redir := authResponse(c.RedirectURI, c.State)
	v := redir.Query()
	v.Add("code", c.Code)
	redir.RawQuery = v.Encode()
	return redir
}

// SendCodeAuthResponse sends the appropriate response to an auth request of
// response_type code, aka "Code flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2
func SendCodeAuthResponse(w http.ResponseWriter, req *http.Request, resp *CodeAuthResponse) {
	http.Redirect(w, req, resp.ToRedirectURI().String(), http.StatusFound)
}

type TokenType string

const ( // https://tools.ietf.org/html/rfc6749#section-7.1 , https://tools.ietf.org/html/rfc6750
	TokenTypeBearer TokenType = "Bearer"
)

type TokenAuthResponse struct {
	RedirectURI *url.URL
	State       string
	Token       string
	TokenType   TokenType
	Scopes      []string
	ExpiresIn   time.Duration
}

// SendTokenAuthResponse sends the appropriate response to an auth request of
// response_type token, aka "Implicit flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.2.2
func SendTokenAuthResponse(w http.ResponseWriter, req *http.Request, resp *TokenAuthResponse) {
	redir := authResponse(resp.RedirectURI, resp.State)
	v := redir.Query()
	v.Add("access_token", resp.Token)
	v.Add("token_type", string(resp.TokenType))
	if resp.ExpiresIn != 0 {
		v.Add("expires_in", fmt.Sprintf("%d", int(resp.ExpiresIn.Seconds())))
	}
	if resp.Scopes != nil {
		v.Add("scope", strings.Join(resp.Scopes, " "))
	}
	redir.RawQuery = v.Encode()
	http.Redirect(w, req, redir.String(), http.StatusFound)
}

func authResponse(redir *url.URL, state string) *url.URL {
	v := redir.Query()
	if state != "" {
		v.Add("state", state)
	}
	redir.RawQuery = v.Encode()
	return redir
}
