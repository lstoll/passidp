package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/alecthomas/kong"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/oklog/run"
	"golang.org/x/oauth2"
	clitoken "lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/oauth2client"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
	"lds.li/passidp/internal/admincli"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/idp"
	"lds.li/passidp/internal/policy"
	"lds.li/passidp/internal/storage"
)

// browserStepTimeout returns a duration to timeout browser operations. It defaults
// towards failing tests within a reasonable time, but allows an env var to
// greatly extend this when you want to interact with the browser
func browserStepTimeout() time.Duration {
	if et, _ := strconv.ParseBool(os.Getenv("TEST_E2E_EXTEND_TIMEOUT")); et {
		return 60 * time.Second
	}
	return 5 * time.Second
}

const testUserID = "4854735c-5a01-4a2d-b7a0-330a5b5928a9"

func TestE2E(t *testing.T) {
	runE2E, _ := strconv.ParseBool(os.Getenv("TEST_E2E"))
	runE2EHeadless, _ := strconv.ParseBool(os.Getenv("TEST_E2E_HEADLESS"))
	if !runE2E && !runE2EHeadless {
		t.Skip("TEST_E2E or TEST_E2E_HEADLESS not true")
	}

	/* set up a chrome instance */
	opts := chromedp.DefaultExecAllocatorOptions[:]
	if !runE2EHeadless {
		opts = append(opts, chromedp.Flag("headless", false))
	}
	if goruntime.GOOS == "linux" && os.Getenv("GITHUB_ACTIONS") != "" {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	// Add flags to ignore certificate errors for self-signed certificates
	opts = append(opts,
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("ignore-ssl-errors", true),
		chromedp.Flag("ignore-certificate-errors-spki-list", ""),
		chromedp.Flag("allow-insecure-localhost", true),
	)
	allocCtx, execCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(execCancel)

	ctx, chromeCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
	t.Cleanup(chromeCancel)

	var (
		// chromeErrC gets a message when an error occurs in the browser
		// runtime, e.g js errors
		chromeErrC = make(chan error, 10000)
	)
	chromedp.ListenTarget(ctx, func(ev any) {
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			t.Logf("*BROWSER* console.%s call:", ev.Type)
			for _, arg := range ev.Args {
				t.Logf("%s - %s\n", arg.Type, arg.Value)
			}
		case *runtime.EventExceptionThrown:
			s := ev.ExceptionDetails.Error()
			t.Logf("*BROWSER* runtime exception: %s", s)
			chromeErrC <- errors.New(s)
		case *page.EventJavascriptDialogOpening:
			t.Logf("*BROWSER* js dialog: %s", ev.Message)
			go func() {
				if err := chromedp.Run(ctx, page.HandleJavaScriptDialog(true)); err != nil {
					t.Logf("handle js dialog: %v", err)
				}
			}()
		}
	})

	/* start an instance of the server */
	dataDir := t.TempDir()
	credstorePath := dataDir + "/credential-store.json"
	statePath := dataDir + "/state.sqlite"
	storePaths := admincli.Paths{
		CredentialStorePath: credstorePath,
		StatePath:           statePath,
	}

	port := mustAllocatePort()

	os.Setenv("ISSUER_URL", "https://localhost:"+port)
	t.Cleanup(func() {
		os.Unsetenv("ISSUER_URL")
	})

	cfgb, err := os.ReadFile("testdata/config.hujson")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	config, err := config.ParseConfig(kong.NamedFileContentFlag{
		Filename: "testdata/config.hujson",
		Contents: cfgb,
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if err := policy.ValidatePolicies(config); err != nil {
		t.Fatalf("validate policies: %v", err)
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	t.Cleanup(serveCancel)

	certPath, keyPath := GenerateTestCert(t)

	// Configure http.DefaultClient to trust our test certificate
	configureDefaultClientToTrustCert(t, certPath)

	serveErr := make(chan error, 1)
	go func() {
		var (
			g    run.Group
			endC = make(chan struct{}, 1)
		)
		g.Add(func() error {
			<-endC
			return nil
		}, func(error) {
			endC <- struct{}{}
		})
		t.Cleanup(func() {
			endC <- struct{}{}
		})

		idpCmd := &idp.ServeCmd{
			ListenAddr: net.JoinHostPort("localhost", port),
			CertFile:   certPath,
			KeyFile:    keyPath,
		}
		serveErr <- idpCmd.Run(serveCtx, config, storePaths)
	}()

	select {
	case err := <-serveErr:
		t.Fatalf("starting server: %v", err)
	case <-waitListen(ctx, net.JoinHostPort("localhost", port)):
		// continue
	case <-time.After(2 * time.Second):
		t.Fatal("server startup timed out")
	}

	provider, err := provider.DiscoverOIDCProvider(ctx, config.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	oa2Cfg := oauth2.Config{
		ClientID: "test-cli",
		Endpoint: provider.Endpoint(),
		Scopes:   []string{oidc.ScopeOpenID},
	}

	/* enable the virtual webauthn environment */
	var virtAuthenticatorID cdpwebauthn.AuthenticatorID

	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			ep := cdpwebauthn.Enable()
			ep.EnableUI = false // want it to be auto/headless
			if err := ep.Do(ctx); err != nil {
				return fmt.Errorf("enabling webauthn: %v", err)
			}
			ap := cdpwebauthn.AddVirtualAuthenticator(&cdpwebauthn.VirtualAuthenticatorOptions{
				Protocol:                 cdpwebauthn.AuthenticatorProtocolCtap2,
				Transport:                cdpwebauthn.AuthenticatorTransportInternal,
				HasResidentKey:           true,
				HasUserVerification:      true,
				DefaultBackupEligibility: false,
				DefaultBackupState:       false,
				// want to be headless/non-interactive
				AutomaticPresenceSimulation: true,
				IsUserVerified:              true,
			})
			aid, err := ap.Do(ctx)
			if err != nil {
				return fmt.Errorf("adding virtual authenticator: %v", err)
			}
			virtAuthenticatorID = aid
			return nil
		}),
	); err != nil {
		t.Fatalf("running webauthn enablement actions: %v", err)
	}

	_ = virtAuthenticatorID

	/* start testing */

	testOk := t.Run("Registration", func(t *testing.T) {
		var enrollBuf bytes.Buffer
		addCredCmd := &admincli.AddCredentialCmd{
			UserID: testUserID,
			Output: &enrollBuf,
		}
		if err := addCredCmd.Run(ctx, config, storePaths); err != nil {
			t.Fatalf("enrolling user: %v", err)
		}

		// Parse the enrollment URL from enrollBuf
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
			err := chromedp.Run(ctx,
				chromedp.Navigate(enrollmentURL),
				chromedp.WaitVisible(`#register-button`),
				chromedp.SendKeys(`#keyName`, "Test Passkey"),
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
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		case <-doneC:
		}

		credStore, err := storage.NewCredentialFile(credstorePath)
		if err != nil {
			t.Fatalf("open credential store: %v", err)
		}

		credStore.Read(func(cs *storage.CredentialStore) {
			if len(cs.Credentials) != 0 {
				t.Fatalf("new enrollments should not write legacy credentials, got %d", len(cs.Credentials))
			}
			n := 0
			for _, user := range cs.Users {
				n += len(user.Passkeys)
				for _, passkey := range user.Passkeys {
					if !strings.HasPrefix(passkey.Record, "$webauthn$v=1$") {
						t.Fatalf("expected C2SP passkey record, got %q", passkey.Record)
					}
				}
			}
			if n == 0 {
				t.Fatalf("expected at least 1 passkey, got: %d", n)
			}
		})
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Successful Login", func(t *testing.T) {
		tokC, loginErrC := cliLoginFlow(ctx, t, oa2Cfg, oauth2client.PublicClient)

		runErrC := make(chan error, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Sleep(1*time.Second),
			)
			if err != nil {
				runErrC <- err
			}
		}()

		select {
		case tok := <-tokC:
			uinfo := make(map[string]any)
			err := provider.Userinfo(ctx, oa2Cfg.TokenSource(ctx, tok), &uinfo)
			if err != nil {
				t.Fatalf("getting userinfo: %v", err)
			}
			t.Logf("userinfo: %#v", uinfo)
		case err := <-loginErrC:
			t.Fatalf("error in CLI flow: %v", err)
		case err := <-runErrC:
			t.Fatalf("running browser steps: %v", err)
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Groups Test", func(t *testing.T) {
		// Test OIDC flow to verify groups claim is included
		tokC, loginErrC := cliLoginFlow(ctx, t, oa2Cfg, oauth2client.PublicClient)

		runErrC := make(chan error, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Sleep(1*time.Second),
			)
			if err != nil {
				runErrC <- err
			}
		}()

		select {
		case tok := <-tokC:
			uinfo := make(map[string]any)
			err := provider.Userinfo(ctx, oa2Cfg.TokenSource(ctx, tok), &uinfo)
			if err != nil {
				t.Fatalf("getting userinfo: %v", err)
			}
			t.Logf("userinfo: %#v", uinfo)

			// Check that groups claim is present
			if groups, ok := uinfo["groups"]; ok {
				groupsList, ok := groups.([]any)
				if !ok {
					t.Fatalf("groups claim is not a list: %T", groups)
				}
				if len(groupsList) == 0 {
					t.Fatalf("groups claim is empty")
				}
				found := false
				for _, g := range groupsList {
					if g == "test-group" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected group 'test-group' not found in groups claim: %v", groupsList)
				}
				t.Logf("groups claim verified: %v", groupsList)
			} else {
				t.Fatalf("groups claim not found in userinfo")
			}
		case err := <-loginErrC:
			t.Fatalf("error in CLI flow: %v", err)
		case err := <-runErrC:
			t.Fatalf("running browser steps: %v", err)
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Add Credential", func(t *testing.T) {
		before := passkeyNames(t, credstorePath)

		// excludeCredentials now correctly refuses a second resident key on
		// the same authenticator; clear it first to simulate a second device.
		if err := chromedp.Run(ctx, cdpwebauthn.ClearCredentials(virtAuthenticatorID)); err != nil {
			t.Fatal(err)
		}

		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Navigate(config.Issuer+"/"),
				chromedp.WaitVisible(`#credentials-list`),
				chromedp.Click(`a[href="/registration"]`),
				chromedp.WaitVisible(`#register-button`),
				chromedp.SendKeys(`#keyName`, "Home Passkey"),
				chromedp.Click(`#register-button`),
				chromedp.WaitVisible(`#success-message`),
			)
			if err != nil {
				runErrC <- err
			}
			doneC <- struct{}{}
		}()

		select {
		case err := <-runErrC:
			t.Fatalf("running browser steps: %v", err)
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		case <-doneC:
		}

		got := passkeyNames(t, credstorePath)
		if len(got) != len(before)+1 {
			t.Fatalf("passkeys after add = %q, want one more than %q", got, before)
		}
		if !slices.Contains(got, "Home Passkey") {
			t.Fatalf("passkeys after add = %q, want Home Passkey", got)
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Delete Credential", func(t *testing.T) {
		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			err := chromedp.Run(ctx,
				chromedp.Navigate(config.Issuer+"/"),
				chromedp.WaitVisible(`#credentials-list`),
				chromedp.Poll(`document.querySelectorAll('#credentials-table-body tr').length >= 2`, nil, chromedp.WithPollingTimeout(browserStepTimeout())),
				chromedp.Click(`//tr[contains(., 'Home Passkey')]//button[contains(@class, 'delete-credential')]`, chromedp.BySearch),
				chromedp.Poll(`document.querySelectorAll('#credentials-table-body tr').length === 1`, nil, chromedp.WithPollingTimeout(browserStepTimeout())),
			)
			if err != nil {
				runErrC <- err
			}
			doneC <- struct{}{}
		}()

		select {
		case err := <-runErrC:
			t.Fatalf("running browser steps: %v", err)
		case err := <-chromeErrC:
			t.Fatalf("error in browser runtime: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("step timed out")
		case <-doneC:
		}

		got := passkeyNames(t, credstorePath)
		if slices.Contains(got, "Home Passkey") {
			t.Fatalf("Home Passkey still present after delete: %q", got)
		}
		if len(got) == 0 {
			t.Fatal("expected the original passkey to remain")
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)

	testOk = t.Run("Failed Login", func(t *testing.T) {
		// remove all credentials, test the case where it fails.
		if err := chromedp.Run(ctx,
			cdpwebauthn.ClearCredentials(virtAuthenticatorID),
		); err != nil {
			t.Fatal(err)
		}

		// and log out, so there's no session cache
		if err := chromedp.Run(ctx,
			chromedp.Navigate(config.Issuer+"/logout"),
		); err != nil {
			t.Fatal(err)
		}

		tokC, errC := cliLoginFlow(ctx, t, oa2Cfg, oauth2client.PublicClient)

		runErrC := make(chan error, 1)
		doneC := make(chan struct{}, 1)
		go func() {
			var errorText string
			err := chromedp.Run(ctx,
				// wait for error message to appear and get its text
				chromedp.WaitVisible(`#error-message`),
				chromedp.Text(`#error-message`, &errorText),
			)
			if err != nil {
				runErrC <- err
				return
			}

			if !strings.Contains(strings.ToLower(errorText), "failed") {
				runErrC <- fmt.Errorf("expected error message to contain 'failed', got: %s", errorText)
				return
			}

			t.Logf("found expected error message: %s", errorText)
			doneC <- struct{}{}
		}()

		select {
		case bErr := <-chromeErrC:
			// this is for unhandled exceptions
			t.Logf("expected browser error returned: %v", bErr)
		case cdpErr := <-runErrC:
			t.Fatalf("chromedp error: %v", cdpErr)
		case gt := <-tokC:
			t.Fatalf("no creds should have got us no token, but got: %v", gt)
		case err := <-errC:
			t.Fatalf("error triggering CLI flow: %v", err)
		case <-time.After(browserStepTimeout()):
			t.Fatal("timed out waiting for token")
		case <-doneC:
		}
	})
	if !testOk {
		t.Fatal("dependent step failed, aborting")
	}
	clearErrchan(chromeErrC)
}

// cliLoginFlow starts a login flow via the oidc cli library. It will trigger
// the browser instance associated with ctx to navigate to the login page. When
// the flow completes, the resulting OIDC token will be returned on the channel.
// If an error occurs, that will be returned on that channel. It is the callers
// responsibility to complete the flow - this will only get you to the initial
// URL for the flow.
func cliLoginFlow(ctx context.Context, t *testing.T, oa2Cfg oauth2.Config, clientType oauth2client.ClientType) (chan *oauth2.Token, chan error) { //nolint:thelper // it's not that kind of helper
	openCh := make(chan struct{}, 1)

	clicfg := clitoken.Config{
		OAuth2Client: &oa2Cfg,
		ClientType:   clientType,
		Opener:       &chromeDPOpener{notifyCh: openCh},
	}

	cli, err := clicfg.TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tokC := make(chan *oauth2.Token, 1)
	errC := make(chan error, 10)

	go func() {
		tok, err := cli.Token()
		if err != nil {
			t.Logf("getting token: %v", err)
			errC <- err
			return
		}
		tokC <- tok
	}()

	select {
	case <-openCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("browser not open for token flow within timeout")
	}

	return tokC, errC
}

// configureDefaultClientToTrustCert modifies http.DefaultClient to trust the certificate at certPath
func configureDefaultClientToTrustCert(t *testing.T, certPath string) {
	t.Helper()

	// Read the certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading certificate file: %v", err)
	}

	// Create a certificate pool and add our certificate
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certData) {
		t.Fatal("failed to append certificate to pool")
	}

	// Modify http.DefaultClient to trust our certificate
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
}

func mustAllocatePort() string {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		panic(err)
	}
	if err := l.Close(); err != nil {
		panic(err)
	}
	return port
}

func waitListen(ctx context.Context, addr string) chan struct{} {
	c := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err != nil {
				continue
			}
			c <- struct{}{}
		}
	}()
	return c
}

// logAction can be dropped into a chromedp.Run, to do some classic printf
// troubleshooting
//
//nolint:unparam // we use this on and off
func logAction(tb testing.TB, format string, args ...any) chromedp.Action { //nolint:unused // keep it, it's regularly useful
	tb.Helper()

	return chromedp.ActionFunc(func(context.Context) error {
		tb.Logf(format, args...)
		return nil
	})
}

func clearErrchan(c chan error) {
loop:
	for {
		select {
		case <-c:
		default:
			break loop
		}
	}
}

func passkeyNames(t *testing.T, path string) []string {
	t.Helper()
	credStore, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	credStore.Read(func(cs *storage.CredentialStore) {
		for _, user := range cs.Users {
			for _, passkey := range user.Passkeys {
				names = append(names, passkey.Name)
			}
		}
	})
	return names
}

// chromeDPopener is an opener that uses chromedp. It assume the context passed
// to Open contains a chromedp handle.
type chromeDPOpener struct {
	// notifyCh will get messages sent when something is opened, if not nil
	notifyCh chan struct{}
}

// Open the URL with the chromedp instance in the given context.
func (c *chromeDPOpener) Open(ctx context.Context, url string) error {
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
	); err != nil {
		return fmt.Errorf("opening url: %v", err)
	}
	if c.notifyCh != nil {
		c.notifyCh <- struct{}{}
	}
	return nil
}
