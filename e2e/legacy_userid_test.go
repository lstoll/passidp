package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"golang.org/x/oauth2"
	"lds.li/passidp/internal/admincli"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

func TestE2ELegacyUserIDs(t *testing.T) {
	runE2E, _ := strconv.ParseBool(os.Getenv("TEST_E2E"))
	runE2EHeadless, _ := strconv.ParseBool(os.Getenv("TEST_E2E_HEADLESS"))
	if !runE2E && !runE2EHeadless {
		t.Skip("TEST_E2E or TEST_E2E_HEADLESS not true")
	}

	h := startE2E(t, func(cfg *config.Config, store *storage.CredentialFile) error {
		return store.Write(func(cs *storage.CredentialStore) error {
			for _, u := range cfg.Users {
				pu := cs.EnsurePasskeyUser(u.ID, u.PasskeyHandleAliases())
				switch u.Email {
				case "uuid-string@example.com":
					pu.PasskeyUserID = u.ID.String()
				case "subject@example.com":
					pu.PasskeyUserID = "legacy-subject"
				}
			}
			return nil
		})
	})

	cases := []struct {
		name      string
		userID    string
		wantID    func(*config.User) string
		rewriteTo func(*config.User) []byte // if set, rewrite CDP userHandle after register
	}{
		{
			name:   "account_uuid_string",
			userID: "11111111-1111-4111-8111-111111111111",
			wantID: func(u *config.User) string { return u.ID.String() },
		},
		{
			name:   "override_subject",
			userID: "33333333-3333-4333-8333-333333333333",
			wantID: func(u *config.User) string { return "legacy-subject" },
		},
		{
			name:   "raw_uuid_bytes",
			userID: "55555555-5555-4555-8555-555555555555",
			wantID: func(u *config.User) string { return string(u.WebauthnHandle[:]) },
			rewriteTo: func(u *config.User) []byte {
				return u.WebauthnHandle[:]
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := chromedp.Run(h.ctx, cdpwebauthn.ClearCredentials(h.virtID)); err != nil {
				t.Fatal(err)
			}
			if err := chromedp.Run(h.ctx, chromedp.Navigate(h.cfg.Issuer+"/logout")); err != nil {
				t.Fatal(err)
			}

			user, err := h.cfg.Users.GetUserByStringID(tc.userID)
			if err != nil {
				t.Fatal(err)
			}

			enrollAndRegister(t, h, tc.userID, "Legacy "+tc.name)

			if tc.rewriteTo != nil {
				rewriteAuthenticatorUserHandle(t, h, tc.rewriteTo(user))
			}

			gotHandle := authenticatorUserHandle(t, h)
			want := []byte(tc.wantID(user))
			if !bytes.Equal(gotHandle, want) {
				t.Fatalf("authenticator userHandle = %q (%x), want %q (%x)", gotHandle, gotHandle, want, want)
			}

			tok := loginOIDC(t, h)
			uinfo := make(map[string]any)
			if err := h.provider.Userinfo(h.ctx, h.oa2Cfg.TokenSource(h.ctx, tok), &uinfo); err != nil {
				t.Fatalf("userinfo: %v", err)
			}
			if uinfo["email"] != user.Email {
				t.Fatalf("userinfo email = %v, want %s", uinfo["email"], user.Email)
			}
		})
	}
}

func enrollAndRegister(t *testing.T, h *e2eHarness, userID, keyName string) {
	t.Helper()
	var enrollBuf bytes.Buffer
	addCredCmd := &admincli.AddCredentialCmd{
		UserID: userID,
		Output: &enrollBuf,
	}
	if err := addCredCmd.Run(h.ctx, h.cfg, h.paths); err != nil {
		t.Fatalf("enrolling user: %v", err)
	}

	var enrollmentURL string
	for line := range strings.SplitSeq(enrollBuf.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "Enroll at: "); ok {
			enrollmentURL = strings.TrimSpace(rest)
		}
	}
	if enrollmentURL == "" {
		t.Fatalf("failed to parse enrollment URL from output: %q", enrollBuf.String())
	}

	runErrC := make(chan error, 1)
	doneC := make(chan struct{}, 1)
	go func() {
		err := chromedp.Run(h.ctx,
			chromedp.Navigate(enrollmentURL),
			chromedp.WaitVisible(`#register-button`),
			chromedp.SendKeys(`#keyName`, keyName),
			chromedp.Click(`#register-button`),
			chromedp.WaitVisible(`#success-message`),
			chromedp.Sleep(1*time.Second),
		)
		if err != nil {
			runErrC <- err
		}
		doneC <- struct{}{}
	}()

	select {
	case err := <-runErrC:
		t.Fatalf("running browser steps: %v", err)
	case err := <-h.chromeErrC:
		t.Fatalf("error in browser runtime: %v", err)
	case <-time.After(browserStepTimeout()):
		t.Fatal("step timed out")
	case <-doneC:
	}
}

func loginOIDC(t *testing.T, h *e2eHarness) *oauth2.Token {
	t.Helper()
	tokC, loginErrC := cliLoginFlow(h.ctx, t, h.oa2Cfg, h.clientType)

	select {
	case tok := <-tokC:
		return tok
	case err := <-loginErrC:
		t.Fatalf("error in CLI flow: %v", err)
	case err := <-h.chromeErrC:
		t.Fatalf("error in browser runtime: %v", err)
	case <-time.After(browserStepTimeout()):
		t.Fatal("login timed out")
	}
	return nil
}

func authenticatorUserHandle(t *testing.T, h *e2eHarness) []byte {
	t.Helper()
	var creds []*cdpwebauthn.Credential
	if err := chromedp.Run(h.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		creds, err = cdpwebauthn.GetCredentials(h.virtID).Do(ctx)
		return err
	})); err != nil {
		t.Fatalf("get credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 authenticator credential, got %d", len(creds))
	}
	return decodeCDPBinary(t, creds[0].UserHandle)
}

func rewriteAuthenticatorUserHandle(t *testing.T, h *e2eHarness, handle []byte) {
	t.Helper()
	if err := chromedp.Run(h.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		creds, err := cdpwebauthn.GetCredentials(h.virtID).Do(ctx)
		if err != nil {
			return err
		}
		if len(creds) != 1 {
			return fmt.Errorf("expected 1 credential to rewrite, got %d", len(creds))
		}
		cred := creds[0]
		if err := cdpwebauthn.RemoveCredential(h.virtID, cred.CredentialID).Do(ctx); err != nil {
			return err
		}
		cred.UserHandle = base64.StdEncoding.EncodeToString(handle)
		return cdpwebauthn.AddCredential(h.virtID, cred).Do(ctx)
	})); err != nil {
		t.Fatalf("rewrite userHandle: %v", err)
	}
}

func decodeCDPBinary(t *testing.T, s string) []byte {
	t.Helper()
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b
		}
	}
	t.Fatalf("decode CDP binary %q", s)
	return nil
}
