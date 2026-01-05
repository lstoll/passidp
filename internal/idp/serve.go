package idp

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/alecthomas/kong"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/oauth2ext/oauth2as/discovery"
	"lds.li/web"
	"lds.li/web/csp"
	"lds.li/web/proxyhdrs"
	"lds.li/web/requestid"
	"lds.li/web/session"
	"lds.li/web/session/sqlkv"
	"lds.li/webauthn-oidc-idp/internal/adminui"
	"lds.li/webauthn-oidc-idp/internal/auth"
	"lds.li/webauthn-oidc-idp/internal/clients"
	"lds.li/webauthn-oidc-idp/internal/oidcsvr"
	"lds.li/webauthn-oidc-idp/internal/queries"
	"lds.li/webauthn-oidc-idp/internal/webcommon"
)

type ServeCmd struct {
	ListenAddr        string                    `default:"localhost:8085" env:"IDP_LISTEN_ADDR" help:"Listen address for the server."`
	MetricsAddr       string                    `env:"IDP_METRICS_ADDR" help:"Expose Prometheus metrics on the given host:port."`
	CertFile          string                    `env:"IDP_CERT_FILE" help:"Path to the TLS certificate file."`
	KeyFile           string                    `env:"IDP_KEY_FILE" help:"Path to the TLS key file."`
	StaticClientsFile kong.NamedFileContentFlag `required:"" env:"IDP_STATIC_CLIENTS_FILE" help:"Path to the static clients file."`
}

func (c *ServeCmd) Run(ctx context.Context, db *sql.DB, issuerURL *url.URL) error {
	var g run.Group
	g.Add(run.ContextHandler(ctx))

	staticClients, err := clients.ParseStaticClients(c.StaticClientsFile.Contents)
	if err != nil {
		return fmt.Errorf("loading clients: %v", err)
	}

	// Create dynamic clients
	dynamicClients := &clients.DynamicClients{DB: queries.New(db)}

	// Create multi-clients that combines both
	multiClients := clients.NewMultiClients(staticClients, dynamicClients)

	idph, err := NewIDP(ctx, &g, db, issuerURL, multiClients)
	if err != nil {
		return fmt.Errorf("start server: %v", err)
	}

	mux := http.NewServeMux()

	log.Printf("mountng at hostname %s", issuerURL.Hostname())

	mux.Handle(issuerURL.Hostname()+"/", idph)
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
func NewIDP(ctx context.Context, g *run.Group, sqldb *sql.DB, issuerURL *url.URL, clients *clients.MultiClients) (http.Handler, error) {
	oidcHandles, err := initKeysets(ctx, sqldb)
	if err != nil {
		return nil, fmt.Errorf("initializing keysets: %w", err)
	}

	sesskv := sqlkv.New(sqldb, &sqlkv.Opts{
		TableName: "web_sessions",
		Dialect:   sqlkv.SQLite,
	})

	sessionManager, err := session.NewKVManager(sesskv, nil)
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
		BaseURL:        issuerURL,
		SessionManager: sessionManager,
		Static:         webcommon.Static, // TODO - lstoll/web should not panic when not set
		CSPOpts:        cspOpts,
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

	wn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: issuerURL.Hostname(), // Display Name for your site
		RPID:          issuerURL.Hostname(), // Generally the FQDN for your site
		RPOrigins: []string{
			issuerURL.String(),
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			RequireResidentKey: ptr(true),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring webauthn: %w", err)
	}

	// start configuration of webauthn manager
	mgr := adminui.NewWebAuthnManager(queries.New(sqldb), wn)

	mgr.AddHandlers(websvr)

	auth := &auth.Authenticator{
		Webauthn: wn,
		Queries:  queries.New(sqldb),
	}
	auth.AddHandlers(websvr)

	oidchHandlers := &oidcsvr.Handlers{
		Issuer:  issuerURL.String(),
		Queries: queries.New(sqldb),
		Clients: clients,
	}

	oauth2asConfig := oauth2as.Config{
		Issuer:   issuerURL.String(),
		Storage:  oidcsvr.NewSQLiteStorage(sqldb),
		Clients:  clients,
		Signer:   oidcHandles,
		Verifier: oidcHandles,

		TokenHandler:    oidchHandlers.TokenHandler,
		UserinfoHandler: oidchHandlers.UserinfoHandler,

		Logger: slog.With("component", "oauth2as"),
	}

	oauth2asServer, err := oauth2as.NewServer(oauth2asConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth2as server: %w", err)
	}

	pmd := discovery.DefaultCoreMetadata(issuerURL.String())
	pmd.IDTokenSigningAlgValuesSupported = oidcHandles.SupportedAlgorithms()
	pmd.AuthorizationEndpoint = issuerURL.String() + "/authorization"
	pmd.TokenEndpoint = issuerURL.String() + "/token"
	pmd.UserinfoEndpoint = issuerURL.String() + "/userinfo"
	pmd.RegistrationEndpoint = fmt.Sprintf("%s/registerClient", issuerURL.String())

	disco, err := discovery.NewOIDCConfigurationHandlerWithKeyset(pmd, oidcHandles)
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc configuration handler: %w", err)
	}

	oidcs := oidcsvr.Server{
		Auth:      auth,
		OAuth2AS:  oauth2asServer,
		Discovery: disco,
		DB:        queries.New(sqldb),
		Clients:   clients,
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

	return websvr, nil
}

func ptr[T any](v T) *T {
	return &v
}
