package oauth2proto

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseAuthRequest(t *testing.T) {
	completeQuery := fmt.Sprintf(
		"response_type=code&client_id=client&redirect_uri=%s&scope=%s&state=state",
		url.QueryEscape("https://redirect"), url.QueryEscape("openid groups"),
	)
	completeReq := &AuthRequest{
		ClientID:     "client",
		RedirectURI:  "https://redirect",
		State:        "state",
		Scopes:       []string{"openid", "groups"},
		ResponseType: ResponseTypeCode,
		Raw: url.Values{
			"client_id":     {"client"},
			"redirect_uri":  {"https://redirect"},
			"response_type": {"code"},
			"scope":         {"openid groups"},
			"state":         {"state"},
		},
	}

	for _, tc := range []struct {
		Name        string
		Method      string
		Query       string
		Body        string
		ContentType string
		WantErr     bool
		WantErrCode AuthErrorCode
		CmpReq      *AuthRequest
	}{
		{
			Name:    "Invalid method",
			Method:  "HEAD",
			WantErr: true,
		},
		{
			Name:        "Unknown response type",
			Query:       "response_type=bad",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:        "Missing client ID",
			Query:       "response_type=code",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:   "Complete request",
			Query:  completeQuery,
			CmpReq: completeReq,
		},
		{
			Name: "Invalid PKCE type",
			Query: fmt.Sprintf(
				"response_type=code&client_id=client&redirect_uri=%s&scope=%s&state=state&code_challenge=aaa",
				url.QueryEscape("https://redirect"), url.QueryEscape("openid groups"),
			),
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:        "Invalid max_age",
			Query:       "response_type=code&client_id=client&max_age=bad",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:        "Empty max_age",
			Query:       "response_type=code&client_id=client&max_age=",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:  "max_age zero",
			Query: "response_type=code&client_id=client&max_age=0",
			CmpReq: &AuthRequest{
				ClientID:     "client",
				ResponseType: ResponseTypeCode,
				MaxAge:       new(0),
				Raw: url.Values{
					"client_id":     {"client"},
					"response_type": {"code"},
					"max_age":       {"0"},
				},
			},
		},
		{
			Name:  "max_age set",
			Query: "response_type=code&client_id=client&max_age=3600",
			CmpReq: &AuthRequest{
				ClientID:     "client",
				ResponseType: ResponseTypeCode,
				MaxAge:       new(3600),
				Raw: url.Values{
					"client_id":     {"client"},
					"response_type": {"code"},
					"max_age":       {"3600"},
				},
			},
		},
		{
			Name:        "Reject repeated query parameters",
			Query:       completeQuery + "&redirect_uri=" + url.QueryEscape("https://evil"),
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:        "POST complete request",
			Method:      "POST",
			Body:        completeQuery,
			ContentType: "application/x-www-form-urlencoded",
			CmpReq:      completeReq,
		},
		{
			Name:        "Reject POST query parameters",
			Method:      "POST",
			Query:       "redirect_uri=" + url.QueryEscape("https://evil"),
			Body:        completeQuery,
			ContentType: "application/x-www-form-urlencoded",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:        "Reject repeated POST parameters",
			Method:      "POST",
			Body:        completeQuery + "&client_id=other",
			ContentType: "application/x-www-form-urlencoded",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
		{
			Name:        "Reject POST without form content type",
			Method:      "POST",
			Body:        completeQuery,
			ContentType: "application/json",
			WantErr:     true,
			WantErrCode: AuthErrorCodeInvalidRequest,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			meth := tc.Method
			if meth == "" {
				meth = "GET"
			}

			req := httptest.NewRequest(meth, "https://test/auth", strings.NewReader(tc.Body))
			req.URL.RawQuery = tc.Query
			if tc.ContentType != "" {
				req.Header.Set("Content-Type", tc.ContentType)
			}

			preq, err := ParseAuthRequest(req)
			if err == nil && tc.WantErr {
				t.Fatal("want error, got none")
			}
			if err != nil && !tc.WantErr {
				t.Fatalf("want no err, got: %v", err)
			}
			if err != nil && tc.WantErrCode != AuthErrorCode("") {
				aerr, ok := err.(*AuthError)
				if !ok {
					t.Errorf("want error of type *authError, got %T", err)
				} else if tc.WantErrCode != aerr.Code {
					t.Errorf("want err code %s, got: %s", tc.WantErrCode, aerr.Code)
				}
			}

			if tc.CmpReq != nil {
				if diff := cmp.Diff(tc.CmpReq, preq); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}

func TestSendCodeAuthResponse(t *testing.T) {
	for _, tc := range []struct {
		Name           string
		Resp           *CodeAuthResponse
		WantRedirectTo string
	}{
		{
			Name: "valid response",
			Resp: &CodeAuthResponse{
				RedirectURI: mustURL("https://redirect"),
				State:       "state",
				Code:        "code",
			},
			WantRedirectTo: "https://redirect?code=code&state=state",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://auth", nil)
			w := httptest.NewRecorder()

			SendCodeAuthResponse(w, req, tc.Resp)

			if w.Result().StatusCode < 300 || w.Result().StatusCode > 399 {
				t.Errorf("want redirect status, got %d", w.Result().StatusCode)
			}

			loc := w.Result().Header.Get("location")

			if tc.WantRedirectTo != loc {
				t.Errorf("want redirect to %s, got: %s", tc.WantRedirectTo, loc)
			}
		})
	}
}

func TestSendTokenAuthResponse(t *testing.T) {
	for _, tc := range []struct {
		Name           string
		Resp           *TokenAuthResponse
		WantRedirectTo string
	}{
		{
			Name: "valid response",
			Resp: &TokenAuthResponse{
				RedirectURI: mustURL("https://redirect"),
				State:       "state",
				Token:       "tok",
				TokenType:   TokenTypeBearer,
				Scopes:      []string{"openid"},
				ExpiresIn:   1 * time.Minute,
			},
			WantRedirectTo: "https://redirect?access_token=tok&expires_in=60&scope=openid&state=state&token_type=Bearer",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://auth", nil)
			w := httptest.NewRecorder()

			SendTokenAuthResponse(w, req, tc.Resp)

			if w.Result().StatusCode < 300 || w.Result().StatusCode > 399 {
				t.Errorf("want redirect status, got %d", w.Result().StatusCode)
			}

			loc := w.Result().Header.Get("location")

			if tc.WantRedirectTo != loc {
				t.Errorf("want redirect to %s, got: %s", tc.WantRedirectTo, loc)
			}
		})
	}
}

func mustURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic("err")
	}
	return u
}
