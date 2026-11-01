package oauth2as

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

type UserinfoHandler func(ctx context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error)

// UserinfoRequest contains information about this request to the UserInfo
// endpoint. The handler is responsible for returning only claims permitted by
// GrantedScopes.
type UserinfoRequest struct {
	// Subject is the sub of the user this request is for.
	Subject string
	// GrantID is the ID of the grant associated with the access token.
	GrantID string
	// GrantedScopes are the scopes granted on the associated grant.
	GrantedScopes []string
	// ACR is the Authentication Context Class Reference from the grant.
	ACR string
	// AMR lists the Authentication Methods References from the grant.
	AMR []string
	// AuthenticatedAt is when the End-User last actively authenticated.
	AuthenticatedAt time.Time
	// MaxAge is the max_age from the original authorization request, if any.
	MaxAge *int
}

// UserinfoResponse contains information to response to the userinfo response.
type UserinfoResponse struct {
	// Identity is the identity of the user this request is for, to be JSON
	// serialized.
	Identity any
}

// UserinfoHandler verifies the access token, loads and validates its grant,
// and invokes the configured handler. Claim selection by scope remains the
// application handler's responsibility.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (s *Server) UserinfoHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	authorization := req.Header.Values("Authorization")
	if len(authorization) != 1 {
		be := &oauth2proto.BearerError{} // no content, just request auth
		herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "exactly one Authorization header is required"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}
	authScheme, accessToken, ok := strings.Cut(authorization[0], " ")
	if !ok || accessToken == "" || strings.ContainsAny(accessToken, " \t") || (!strings.EqualFold(authScheme, "bearer") && !strings.EqualFold(authScheme, "dpop")) {
		be := &oauth2proto.BearerError{}
		herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}

	atJWT, err := s.verifyAccessToken(accessToken)
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", err)
		return
	}
	dpopThumbprint, err := accessTokenDPoPThumbprint(atJWT)
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token confirmation claim", "error", err)
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", err)
		return
	}
	if dpopThumbprint == "" {
		if !strings.EqualFold(authScheme, "bearer") {
			writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "DPoP authorization is only valid for DPoP-bound tokens", nil)
			return
		}
	} else {
		if !strings.EqualFold(authScheme, "dpop") {
			writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "DPoP-bound token requires DPoP authorization", nil)
			return
		}
		if _, err := s.verifyDPoPProof(s.config.Issuer, req, &dpopThumbprint, accessToken); err != nil {
			slog.ErrorContext(req.Context(), "invalid DPoP proof for userinfo", "error", err)
			writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid DPoP proof", err)
			return
		}
	}

	atSub, err := atJWT.Subject()
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", err)
		return
	}

	grantID, err := atJWT.String(claimGrantID)
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token grant ID claim", "error", err)
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", err)
		return
	}
	tokenClientID, err := atJWT.String("client_id")
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token client ID claim", "error", err)
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", err)
		return
	}
	grant, err := s.config.Storage.getGrant(req.Context(), grantID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			slog.WarnContext(req.Context(), "grant not found for access token", "grantID", grantID)
			writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", err)
			return
		}
		slog.ErrorContext(req.Context(), "failed to load grant for userinfo", "grantID", grantID, "error", err)
		herr := &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error loading grant"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}
	if !grant.ExpiresAt.After(s.now()) {
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", nil)
		return
	}
	if tokenClientID != grant.ClientID {
		writeUserinfoBearerError(w, req, oauth2proto.BearerErrorCodeInvalidToken, "invalid access token", nil)
		return
	}
	if !slices.Contains(grant.GrantedScopes, oidc.ScopeOpenID) {
		be := &oauth2proto.BearerError{Code: oauth2proto.BearerErrorCodeInsufficientScope, Description: "openid scope required"}
		herr := &oauth2proto.HTTPError{Code: http.StatusForbidden, WWWAuthenticate: be.String(), CauseMsg: "openid scope required"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}
	uireq := &UserinfoRequest{
		Subject: atSub,
		GrantID: grantID,

		GrantedScopes:   slices.Clone(grant.GrantedScopes),
		ACR:             grant.ACR,
		AMR:             slices.Clone(grant.AMR),
		AuthenticatedAt: authTimeFromGrant(grant),
		MaxAge:          maxAgeFromGrant(grant),
	}

	w.Header().Set("Content-Type", "application/json")

	uiresp, err := s.config.UserinfoHandler(req.Context(), uireq)
	if err != nil {
		herr := &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error in user handler"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}
	if uiresp.Identity == nil {
		herr := &oauth2proto.HTTPError{Code: http.StatusInternalServerError, CauseMsg: "userinfo has no identity"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}

	// TODO: Pre-populate standard claims (iss, aud, etc.) in the identity response

	if err := json.NewEncoder(w).Encode(uiresp.Identity); err != nil {
		_ = oauth2proto.WriteError(w, req, err)
		return
	}
}

func accessTokenDPoPThumbprint(atJWT *jwt.VerifiedJWT) (string, error) {
	if !atJWT.Has("cnf") {
		return "", nil
	}
	cnf, err := atJWT.Object("cnf")
	if err != nil {
		return "", err
	}
	jkt, ok := cnf["jkt"].(string)
	if !ok || jkt == "" || len(cnf) != 1 {
		return "", fmt.Errorf("invalid cnf.jkt claim")
	}
	return jkt, nil
}

func writeUserinfoBearerError(w http.ResponseWriter, req *http.Request, code oauth2proto.BearerErrorCode, description string, cause error) { // nolint:unparam // code may vary in future.
	bearerError := &oauth2proto.BearerError{Code: code, Description: description}
	httpError := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: bearerError.String(), Cause: cause}
	_ = oauth2proto.WriteError(w, req, httpError)
}

func (s *Server) verifyAccessToken(compact string) (*jwt.VerifiedJWT, error) {
	if s == nil || s.accessTokenVerifier == nil {
		return nil, fmt.Errorf("verifying and decoding access token: verifier is unavailable")
	}
	vjwt, err := s.accessTokenVerifier.Verify(compact)
	if err != nil {
		return nil, fmt.Errorf("verifying and decoding access token: %w", err)
	}
	return vjwt, nil
}
