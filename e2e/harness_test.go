package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	goruntime "runtime"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/oklog/run"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oauth2client"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
	"lds.li/passidp/internal/admincli"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/idp"
	"lds.li/passidp/internal/policy"
	"lds.li/passidp/internal/storage"
)

type e2eHarness struct {
	ctx        context.Context
	cfg        *config.Config
	paths      admincli.Paths
	chromeErrC chan error
	virtID     cdpwebauthn.AuthenticatorID
	provider   *provider.Provider
	oa2Cfg     oauth2.Config
	clientType oauth2client.ClientType
}

func startE2E(t *testing.T, seed func(*config.Config, *storage.CredentialFile) error) *e2eHarness {
	t.Helper()

	opts := chromedp.DefaultExecAllocatorOptions[:]
	runE2EHeadless, _ := strconv.ParseBool(os.Getenv("TEST_E2E_HEADLESS"))
	if !runE2EHeadless {
		opts = append(opts, chromedp.Flag("headless", false))
	}
	if goruntime.GOOS == "linux" && os.Getenv("GITHUB_ACTIONS") != "" {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
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

	chromeErrC := make(chan error, 10000)
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

	dataDir := t.TempDir()
	credstorePath := dataDir + "/credential-store.json"
	statePath := dataDir + "/state.sqlite"
	paths := admincli.Paths{
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
	cfg, err := config.ParseConfig(kong.NamedFileContentFlag{
		Filename: "testdata/config.hujson",
		Contents: cfgb,
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := policy.ValidatePolicies(cfg); err != nil {
		t.Fatalf("validate policies: %v", err)
	}

	if seed != nil {
		store, err := storage.NewCredentialFile(credstorePath)
		if err != nil {
			t.Fatalf("open credential store: %v", err)
		}
		if err := seed(cfg, store); err != nil {
			t.Fatalf("seed credential store: %v", err)
		}
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	t.Cleanup(serveCancel)

	certPath, keyPath := GenerateTestCert(t)
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
		serveErr <- idpCmd.Run(serveCtx, cfg, paths)
	}()

	select {
	case err := <-serveErr:
		t.Fatalf("starting server: %v", err)
	case <-waitListen(ctx, net.JoinHostPort("localhost", port)):
	case <-time.After(2 * time.Second):
		t.Fatal("server startup timed out")
	}

	oidcProvider, err := provider.DiscoverOIDCProvider(ctx, cfg.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	oa2Cfg := oauth2.Config{
		ClientID: "test-cli",
		Endpoint: oidcProvider.Endpoint(),
		Scopes:   []string{oidc.ScopeOpenID},
	}

	var virtID cdpwebauthn.AuthenticatorID
	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			ep := cdpwebauthn.Enable()
			ep.EnableUI = false
			if err := ep.Do(ctx); err != nil {
				return fmt.Errorf("enabling webauthn: %v", err)
			}
			ap := cdpwebauthn.AddVirtualAuthenticator(&cdpwebauthn.VirtualAuthenticatorOptions{
				Protocol:                    cdpwebauthn.AuthenticatorProtocolCtap2,
				Transport:                   cdpwebauthn.AuthenticatorTransportInternal,
				HasResidentKey:              true,
				HasUserVerification:         true,
				DefaultBackupEligibility:    false,
				DefaultBackupState:          false,
				AutomaticPresenceSimulation: true,
				IsUserVerified:              true,
			})
			aid, err := ap.Do(ctx)
			if err != nil {
				return fmt.Errorf("adding virtual authenticator: %v", err)
			}
			virtID = aid
			return nil
		}),
	); err != nil {
		t.Fatalf("running webauthn enablement actions: %v", err)
	}

	return &e2eHarness{
		ctx:        ctx,
		cfg:        cfg,
		paths:      paths,
		chromeErrC: chromeErrC,
		virtID:     virtID,
		provider:   oidcProvider,
		oa2Cfg:     oa2Cfg,
		clientType: oauth2client.PublicClient,
	}
}
