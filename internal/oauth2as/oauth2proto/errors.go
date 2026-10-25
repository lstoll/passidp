package oauth2proto

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WriteError handles the passed error appropriately. After calling this, the
// HTTP sequence should be considered complete.
//
// For errors in the authorization endpoint, the user will be redirected with
// the code appended to the redirect URL.
// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
//
// For unknown errors, an InternalServerError response will be sent
func WriteError(w http.ResponseWriter, req *http.Request, err error) error {
	switch err := err.(type) {
	case *AuthError:
		if err.RedirectURI == "" {
			msg := err.Description
			if msg == "" {
				msg = string(err.Code)
			}
			http.Error(w, msg, http.StatusBadRequest)
			return nil
		}
		redir, perr := url.Parse(err.RedirectURI)
		if perr != nil {
			return fmt.Errorf("failed to parse redirect URI %q: %w", err.RedirectURI, perr)
		}
		v := redir.Query()
		if err.State != "" {
			v.Add("state", err.State)
		}
		v.Add("error", string(err.Code))
		if err.Description != "" {
			v.Add("error_description", err.Description)
		}
		redir.RawQuery = v.Encode()
		http.Redirect(w, req, redir.String(), http.StatusFound)

	case *HTTPError:
		m := err.Message
		if m == "" {
			m = "Internal error"
		}
		if err.WWWAuthenticate != "" {
			w.Header().Add("WWW-Authenticate", err.WWWAuthenticate)
		}
		code := err.Code
		if code == 0 {
			code = http.StatusInternalServerError
		}
		http.Error(w, m, code)

	case *TokenError:
		w.Header().Add("Content-Type", "application/json;charset=UTF-8")
		// https://tools.ietf.org/html/rfc6749#section-5.2
		if err.ErrorCode == TokenErrorCodeInvalidClient {
			if err.WWWAuthenticate != "" {
				w.Header().Add("WWW-Authenticate", err.WWWAuthenticate)
			}
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return fmt.Errorf("failed to write token error json body: %w", err)
		}

	default:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	return nil
}

type HTTPError struct {
	Code int
	// Message is presented to the user, so this should be considered.
	// if it's not set, "Internal error" will be used.
	Message string
	// CauseMsg is included in Error() output and can contain internal details.
	CauseMsg string
	Cause    error
	// WWWAuthenticate is passed in the appropriate header field in the response
	WWWAuthenticate string
}

func (h *HTTPError) Error() string {
	m := h.CauseMsg
	if m == "" {
		m = h.Message
	}
	str := fmt.Sprintf("http error %d: %s", h.Code, m)
	if h.Cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, h.Cause.Error())
	}
	return str
}

func (h *HTTPError) Unwrap() error {
	return h.Cause
}

// WriteHTTPError will build and send an httpErr for this HTTP response cycle,
// returning the error that was written. It will ignore any errors actually
// writing the error to the user.
func WriteHTTPError(w http.ResponseWriter, req *http.Request, code int, message string, cause error, causeMsg string) error {
	err := &HTTPError{
		Code:     code,
		Message:  message,
		Cause:    cause,
		CauseMsg: causeMsg,
	}
	_ = WriteError(w, req, err)
	return err
}

type AuthErrorCode string

// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
// nolint:unused
const (
	AuthErrorCodeInvalidRequest           AuthErrorCode = "invalid_request"
	AuthErrorCodeUnauthorizedClient       AuthErrorCode = "unauthorized_client"
	AuthErrorCodeAccessDenied             AuthErrorCode = "access_denied"
	AuthErrorCodeUnsupportedResponseType  AuthErrorCode = "unsupported_response_type"
	AuthErrorCodeInvalidScope             AuthErrorCode = "invalid_scope"
	AuthErrorCodeErrServerError           AuthErrorCode = "server_error"
	AuthErrorCodeErrTemporarilyUnvailable AuthErrorCode = "temporarily_unavailable"
)

type AuthError struct {
	State       string
	Code        AuthErrorCode
	Description string
	RedirectURI string
	Cause       error
}

func (a *AuthError) Error() string {
	str := fmt.Sprintf("%s error in authorization request: %s", a.Code, a.Description)
	if a.Cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, a.Cause.Error())
	}
	return str
}

func (a *AuthError) Unwrap() error {
	return a.Cause
}

// WriteAuthError will build and send an authError for this HTTP response cycle,
// returning the error that was written. It will ignore any errors actually
// writing the error to the user.
func WriteAuthError(w http.ResponseWriter, req *http.Request, redirectURI *url.URL, code AuthErrorCode, state, description string, cause error) error {
	err := &AuthError{
		State:       state,
		Code:        code,
		Description: description,
		RedirectURI: redirectURI.String(),
		Cause:       cause,
	}
	_ = WriteError(w, req, err)
	return err
}

// addRedirectToError can attach a redirect URI to an error. This is uncommon,
// but useful when the redirect URI is configured at the client only, and not
// passed in the authorization request. If the error cannot make use of this, it
// will be ignored and the original error returned
func addRedirectToError(err error, redirectURI string) error { //nolint:unparam,unused
	if err, ok := err.(*AuthError); ok {
		err.RedirectURI = redirectURI
		return err
	}
	return err
}

type BearerErrorCode string

// https://tools.ietf.org/html/rfc6750#section-3.1
// nolint:unused
const (
	// The request is missing a required parameter, includes an unsupported
	// parameter or parameter value, repeats the same parameter, uses more than
	// one method for including an access token, or is otherwise malformed.  The
	// resource server SHOULD respond with the HTTP 400 (Bad Request) status
	// code.
	BearerErrorCodeInvalidRequest BearerErrorCode = "invalid_request"
	// The access token provided is expired, revoked, malformed, or invalid for
	// other reasons.  The resource SHOULD respond with the HTTP 401
	// (Unauthorized) status code.  The client MAY request a new access token
	// and retry the protected resource request.
	BearerErrorCodeInvalidToken BearerErrorCode = "invalid_token"
	// The request requires higher privileges than provided by the access token.
	// The resource server SHOULD respond with the HTTP 403 (Forbidden) status
	// code and MAY include the "scope" attribute with the scope necessary to
	// access the protected resource.
	BearerErrorCodeInsufficientScope BearerErrorCode = "insufficient_scope"
)

// BearerError represents the contents that can be returned in the
// www-authenticate header for requests failing to auth under oauth2 bearer
// token usage
//
// https://tools.ietf.org/html/rfc6750#section-3
type BearerError struct {
	Realm       string
	Code        BearerErrorCode
	Description string
}

// String encodes the error in a format suitable for including in a www-authenticate header
func (b *BearerError) String() string {
	ret := []string{}
	if b.Realm != "" {
		ret = append(ret, fmt.Sprintf("%s=%q", "realm", b.Realm))
	}
	if b.Code != "" {
		ret = append(ret, fmt.Sprintf("%s=%q", "error", b.Code))
	}
	if b.Description != "" {
		ret = append(ret, fmt.Sprintf("%s=%q", "error_description", b.Description))
	}
	return "Bearer " + strings.Join(ret, " ")
}

// TokenErrorCode are the types of error that can be returned
type TokenErrorCode string

// https://tools.ietf.org/html/rfc6749#section-5.2
// nolint:unused
const (
	// TokenErrorCodeInvalidRequest: The request is missing a required
	// parameter, includes an unsupported parameter value (other than grant
	// type), repeats a parameter, includes multiple credentials, utilizes more
	// than one mechanism for authenticating the client, or is otherwise
	// malformed.
	TokenErrorCodeInvalidRequest TokenErrorCode = "invalid_request"
	// TokenErrorCodeInvalidClient: Client authentication failed (e.g., unknown
	// client, no client authentication included, or unsupported authentication
	// method).  The authorization server MAY return an HTTP 401 (Unauthorized)
	// status code to indicate which HTTP authentication schemes are supported.
	// If the client attempted to authenticate via the "Authorization" request
	// header field, the authorization server MUST respond with an HTTP 401
	// (Unauthorized) status code and include the "WWW-Authenticate" response
	// header field matching the authentication scheme used by the client.
	TokenErrorCodeInvalidClient TokenErrorCode = "invalid_client"
	// TokenErrorCodeInvalidGrant: The provided authorization grant (e.g.,
	// authorization code, resource owner credentials) or refresh token is
	// invalid, expired, revoked, does not match the redirection URI used in the
	// authorization request, or was issued to another client.
	TokenErrorCodeInvalidGrant TokenErrorCode = "invalid_grant"
	// TokenErrorCodeUnauthorizedClient: The authenticated client is not
	// authorized to use this authorization grant type.
	TokenErrorCodeUnauthorizedClient TokenErrorCode = "unauthorized_client"
	// TokenErrorCodeUnsupportedGrantType: The authorization grant type is not
	// supported by the authorization server.
	TokenErrorCodeUnsupportedGrantType TokenErrorCode = "unsupported_grant_type"
	// TokenErrorCodeInvalidScope: The requested scope is invalid, unknown,
	// malformed, or exceeds the scope granted by the resource owner.
	TokenErrorCodeInvalidScope TokenErrorCode = "invalid_scope"
	// TokenErrorCodeInvalidDPoPProof indicates that a DPoP proof was invalid,
	// including because it was replayed (RFC 9449 section 5).
	TokenErrorCodeInvalidDPoPProof TokenErrorCode = "invalid_dpop_proof"
)

// TokenError represents an error returned from calling the token endpoint.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
type TokenError struct {
	// ErrorCode indicates the type of error that occurred
	ErrorCode TokenErrorCode `json:"error,omitempty"`
	// Description: OPTIONAL.  Human-readable ASCII [USASCII] text providing
	// additional information, used to assist the client developer in
	// understanding the error that occurred. Values for the "error_description"
	// parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
	// %x5D-7E.
	Description string `json:"error_description,omitempty"`
	// ErrorURI: OPTIONAL.  A URI identifying a human-readable web page with
	// information about the error, used to provide the client developer with
	// additional information about the error. Values for the "error_uri"
	// parameter MUST conform to the URI-reference syntax and thus MUST NOT
	// include characters outside the set %x21 / %x23-5B / %x5D-7E.
	ErrorURI string `json:"error_uri,omitempty"`
	// 	WWWAuthenticate is set when an invalid_client error is returned, and
	// 	that response indicates the authentication scheme to be used by the
	// 	client
	WWWAuthenticate string `json:"-"`
	// Cause wraps any upstream error that resulted in this token being issued,
	// if this error should be unwrappable
	Cause error `json:"-"`
}

// Error returns a string representing this error
func (t *TokenError) Error() string {
	str := fmt.Sprintf("%s error in token request: %s", t.ErrorCode, t.Description)
	if t.Cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, t.Cause.Error())
	}
	return str
}

func (t *TokenError) Unwrap() error {
	return t.Cause
}
