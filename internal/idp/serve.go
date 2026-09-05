package idp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"filippo.io/passkey"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"lds.li/keyset"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/oauth2ext/oauth2as/discovery"
	"lds.li/passidp/internal/admincli"
	"lds.li/passidp/internal/adminui"
	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/auth"
	"lds.li/passidp/internal/clients"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oidcsvr"
	"lds.li/passidp/internal/policy"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/session"
	"lds.li/web"
	"lds.li/web/csp"
	"lds.li/web/proxyhdrs"
	"lds.li/web/requestid"
)

const (
	dbscRegistrationPath = "/dbsc/register"
	dbscRefreshPath      = "/dbsc/refresh"
)

type ServeCmd struct {
	ListenAddr  string `default:"localhost:8085" env:"IDP_LISTEN_ADDR" help:"Listen address for the server."`
	MetricsAddr string `env:"IDP_METRICS_ADDR" help:"Expose Prometheus metrics on the given host:port."`
	CertFile    string `env:"IDP_CERT_FILE" help:"Path to the TLS certificate file."`
	KeyFile     string `env:"IDP_KEY_FILE" help:"Path to the TLS key file."`
}

func (c *ServeCmd) Run(ctx context.Context, config *config.Config, paths admincli.Paths) error {
	var g run.Group
	g.Add(run.ContextHandler(ctx))

	credStore, err := storage.NewCredentialFile(paths.CredentialStorePath)
	if err != nil {
		return fmt.Errorf("open credential store from %s: %w", paths.CredentialStorePath, err)
	}

	sqlPath := storage.StateSQLitePath(paths.StatePath)
	sqlDB, err := storage.Open(sqlPath)
	if err != nil {
		return fmt.Errorf("open sqlite state from %s: %w", sqlPath, err)
	}

	oauth2Store, err := storage.NewOAuth2Storage(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("create oauth2 storage: %w", err)
	}
	sessionKV, err := storage.NewSessionKV(sqlDB)
	if err != nil {
		return fmt.Errorf("create session store: %w", err)
	}
	keysetStore, err := storage.NewKeysetStore(sqlDB)
	if err != nil {
		return fmt.Errorf("create keyset store: %w", err)
	}
	enrollmentStore := storage.NewEnrollmentStore(sqlDB)
	dynamicClientStore := storage.NewDynamicClientStore(sqlDB)
	dpopReplayStore := storage.NewDPoPReplayStore(sqlDB)
	oauth2Grants := storage.NewOAuth2Grants(sqlDB)

	g.Add(storage.OAuth2GarbageCollector(oauth2Store, 1*time.Hour))
	g.Add(storage.SessionGarbageCollector(sessionKV, 1*time.Hour))
	g.Add(storage.EnrollmentGarbageCollector(enrollmentStore, 1*time.Hour))
	g.Add(storage.DynamicClientGarbageCollector(dynamicClientStore, 1*time.Hour))
	g.Add(storage.DPoPReplayGarbageCollector(dpopReplayStore, 1*time.Hour))
	g.Add(func() error {
		<-ctx.Done()
		return nil
	}, func(error) {
		if err := sqlDB.Close(); err != nil {
			slog.Error("close sqlite state", slog.String("error", err.Error()))
		}
	})

	multiClients := clients.NewMultiClients(&clients.StaticClients{
		Clients: config.Clients},
		&clients.DynamicClients{DB: dynamicClientStore},
	)

	if err := credStore.ApplyConfig(config.Users, config.ParsedIssuer.Hostname()); err != nil {
		return fmt.Errorf("apply passkey user config: %w", err)
	}

	idph, err := NewIDP(ctx, &g, config, credStore, oauth2Store, sessionKV, keysetStore, enrollmentStore, dpopReplayStore, oauth2Grants, config.ParsedIssuer, multiClients)
	if err != nil {
		return fmt.Errorf("start server: %v", err)
	}

	mux := http.NewServeMux()

	log.Printf("mounting at hostname %s", config.ParsedIssuer.Hostname())

	mux.Handle(config.ParsedIssuer.Hostname()+"/", idph)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World! %s, host: %s", r.URL.Path, r.URL.Hostname())
	}))

	hs := &http.Server{
		Addr:    c.ListenAddr,
		Handler: mux,
	}

	g.Add(func() error {
		if c.CertFile != "" && c.KeyFile != "" {
			slog.Info("server listing", slog.String("addr", "https://"+c.ListenAddr))
			if err := hs.ListenAndServeTLS(c.CertFile, c.KeyFile); err != nil {
				return fmt.Errorf("serving https: %v", err)
			}
		} else {
			slog.Info("server listing", slog.String("addr", "http://"+c.ListenAddr))
			if err := hs.ListenAndServe(); err != nil {
				return fmt.Errorf("serving http: %v", err)
			}
		}
		return nil
	}, func(error) {
		// new context for this, parent is likely already shut down
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})

	{
		if c.MetricsAddr != "" {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			promsrv := &http.Server{Addr: c.MetricsAddr, Handler: mux}

			g.Add(func() error {
				slog.Info("metrics server listing", slog.String("addr", "http://"+c.MetricsAddr))
				if err := promsrv.ListenAndServe(); err != nil {
					return fmt.Errorf("serving metrics: %v", err)
				}
				return nil
			}, func(error) {
				promsrv.Close()
			})
		}
	}

	mux.Handle("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))

	if err := g.Run(); err != nil {
		return fmt.Errorf("run: %v", err)
	}

	return nil
}

// NewIDP creates a new IDP server for the given params.
func NewIDP(ctx context.Context, g *run.Group, cfg *config.Config, credStore *storage.CredentialFile, oauth2 *oauth2as.Storage, sessionKV session.KV, keysetStore keyset.AdminStore, enrollments *storage.EnrollmentStore, dpopReplay dpop.ReplayStore, oauth2Grants *storage.OAuth2Grants, issuerURL *url.URL, clients *clients.MultiClients) (http.Handler, error) {
	oidcSigner, oidcKeys, sessionMAC, err := initKeysets(ctx, keysetStore)
	if err != nil {
		return nil, fmt.Errorf("initializing keysets: %w", err)
	}

	sessionOpts := session.KVManagerOpts[appsession.Data]{
		IdleTimeout:            cfg.SessionDuration.Duration(),
		SessionIDAuthenticator: sessionMAC,
	}
	dbscEnabled := false
	if dbscRefresh := cfg.Serving.DBSCRefreshInterval.Duration(); dbscRefresh > 0 {
		if issuerURL.Scheme != "https" {
			slog.WarnContext(ctx, "DBSC disabled: issuer must use HTTPS", slog.String("issuer", issuerURL.String()))
		} else {
			dbscEnabled = true
			sessionOpts.DBSCRefreshInterval = dbscRefresh
			sessionOpts.DBSCRegistrationPath = dbscRegistrationPath
			sessionOpts.DBSCRefreshPath = dbscRefreshPath
			sessionOpts.DBSCOrigin = issuerURL.Scheme + "://" + issuerURL.Host
			slog.InfoContext(ctx, "DBSC enabled",
				slog.Duration("refresh_interval", dbscRefresh),
				slog.String("origin", sessionOpts.DBSCOrigin),
			)
		}
	}

	sessionManager, err := session.NewKVManager[appsession.Data](sessionKV, &sessionOpts)
	if err != nil {
		return nil, fmt.Errorf("creating session manager: %w", err)
	}

	cspOpts := []csp.HandlerOpt{
		csp.DefaultSrc(`'none'`),
		csp.ImgSrc(`'self'`),
		csp.ConnectSrc(`'self'`),
		csp.FontSrc(`'self'`),
		csp.BaseURI(`'self'`),
		csp.FrameAncestors(`'none'`),
		// end defaults
		csp.ScriptSrc("'self' https://ajax.googleapis.com 'unsafe-inline'"), // TODO - use a nonce
		csp.StyleSrc("'self' 'unsafe-inline'"),                              // TODO - use a nonce
	}

	websvr, err := web.NewServer(&web.Config{
		BaseURL: issuerURL,
		AdditionalBrowserMiddleware: []func(http.Handler) http.Handler{
			func(next http.Handler) http.Handler {
				return sessionManager.Wrap(appsession.Bind(sessionManager)(next))
			},
		},
		Static:  webcommon.Static, // TODO - lstoll/web should not panic when not set
		CSPOpts: cspOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("creating web server: %w", err)
	}
	if err := websvr.BaseMiddleware.Replace(web.MiddlewareRequestIDName, (&requestid.Middleware{
		TrustedHeaders: []string{"Fly-Request-ID"},
	}).Handler); err != nil {
		return nil, fmt.Errorf("replacing request id middleware: %w", err)
	}
	remoteIPMiddleware := &proxyhdrs.RemoteIP{
		ForwardedIPHeader: "Fly-Client-IP",
	}
	websvr.BaseMiddleware.Prepend(web.MiddlewareRequestLogName, remoteIPMiddleware.Handle)

	forceTLSMiddleware := &proxyhdrs.ForceTLS{
		ForwardedProtoHeader: "X-Forwarded-Proto",
	}
	forceTLSMiddleware.AllowBypass("GET /healthz")
	if err := websvr.BaseMiddleware.InsertAfter(web.MiddlewareRequestLogName, forceTLSMiddleware.Handle); err != nil {
		return nil, fmt.Errorf("inserting force tls middleware: %w", err)
	}

	rp, err := passkey.NewRelyingParty(&passkey.Options{
		RPID:   issuerURL.Hostname(),
		Origin: issuerURL.Scheme + "://" + issuerURL.Host,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring passkey relying party: %w", err)
	}

	mgr := adminui.NewWebAuthnManager(cfg, credStore, enrollments, rp)

	mgr.AddHandlers(websvr)

	pol, err := policy.NewPolicyEvaluator()
	if err != nil {
		return nil, fmt.Errorf("creating policy evaluator: %w", err)
	}

	auth := &auth.Authenticator{
		Passkey:      rp,
		CredStore:    credStore,
		OAuth2Grants: oauth2Grants,
		Config:       cfg,
	}
	auth.AddHandlers(websvr)

	oidchHandlers := &oidcsvr.Handlers{
		Issuer:  issuerURL.String(),
		Clients: clients,
		Config:  cfg,
		Policy:  pol,
	}

	dpopVerifier := &dpop.Verifier{
		ReplayStore: dpopReplay,
	}
	if len(cfg.DPoPTrustBundle) > 0 {
		certPool := x509.NewCertPool()
		for _, cert := range cfg.DPoPTrustBundle {
			block, _ := pem.Decode([]byte(cert))
			if block == nil {
				return nil, fmt.Errorf("DPoP trust bundle certificate is not a valid PEM-encoded certificate")
			}
			parsedCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DPoP trust bundle certificate: %w", err)
			}
			certPool.AddCert(parsedCert)
		}
		dpopVerifier.TrustedRoots = certPool
	}

	oauth2asConfig := oauth2as.Config{
		Issuer:           issuerURL.String(),
		Storage:          oauth2,
		Clients:          clients,
		Signer:           oidcSigner,
		VerificationKeys: oidcKeys,

		DPoPVerifier: dpopVerifier,

		TokenHandler:    oidchHandlers.TokenHandler,
		UserinfoHandler: oidchHandlers.UserinfoHandler,

		AccessTokenValidity:             cfg.TokenValidity.Duration(),
		IDTokenValidity:                 cfg.TokenValidity.Duration(),
		RefreshTokenValidity:            cfg.RefreshValidity.Duration(),
		GrantValidity:                   cfg.GrantValidity.Duration(),
		RefreshTokenRotationGracePeriod: cfg.RefreshTokenRotationGracePeriod.Duration(),

		Logger: slog.With("component", "oauth2as"),
	}

	oauth2asServer, err := oauth2as.NewServer(oauth2asConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth2as server: %w", err)
	}
	auth.OAuth2 = oauth2asServer

	pmd := discovery.DefaultCoreMetadata(issuerURL.String())
	pmd.IDTokenSigningAlgValuesSupported = []string{"ES256"}
	pmd.AuthorizationEndpoint = issuerURL.String() + "/authorization"
	pmd.TokenEndpoint = issuerURL.String() + "/token"
	pmd.UserinfoEndpoint = issuerURL.String() + "/userinfo"
	pmd.RegistrationEndpoint = fmt.Sprintf("%s/registerClient", issuerURL.String())

	disco, err := discovery.NewOIDCConfigurationHandlerWithVerificationKeys(pmd, oidcKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc configuration handler: %w", err)
	}

	oidcs := oidcsvr.Server{
		Auth:      auth,
		OAuth2AS:  oauth2asServer,
		Discovery: disco,
		Clients:   clients,
		Config:    cfg,
		Policy:    pol,
	}

	oidcs.AddHandlers(websvr)

	// Add dynamic client registration endpoint
	clients.AddHandlers(websvr)

	// This handles the case where existing running software has discovered
	// /auth as the endpoint, but we renamed it. Just redirect to the new
	// endpoint.
	websvr.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/authorization?"+r.URL.RawQuery, http.StatusSeeOther)
	})

	if dbscEnabled {
		addDBSCRoutes(websvr)
	}

	return websvr, nil
}

// addDBSCRoutes registers browser routes for DBSC so requests reach the session
// middleware. The middleware handles proofs before these handlers run.
func addDBSCRoutes(websvr *web.Server) {
	unreachable := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	websvr.Handle("POST "+dbscRegistrationPath, unreachable, auth.SkipAuthn)
	websvr.Handle("POST "+dbscRefreshPath, unreachable, auth.SkipAuthn)
}
