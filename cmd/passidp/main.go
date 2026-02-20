package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	promversion "github.com/prometheus/common/version"
	"golang.org/x/term"
	"lds.li/passidp/internal/adminapi"
	"lds.li/passidp/internal/admincli"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/idp"
	"lds.li/passidp/internal/policy"
)

const progname = "webauthn-oidc-idp"

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		promversion.Version = info.Main.Version
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if promversion.Revision == "" {
					promversion.Revision = setting.Value
				}
			case "vcs.modified":
				if setting.Value == "true" && promversion.Revision != "" && !strings.HasSuffix(promversion.Revision, "-modified") {
					promversion.Revision += "-modified"
				}
			case "vcs.branch":
				if promversion.Branch == "" {
					promversion.Branch = setting.Value
				}
			}
		}
	}
	prometheus.MustRegister(versioncollector.NewCollector(strings.ReplaceAll(progname, "-", "_")))
}

var rootCmd = struct {
	Debug bool `env:"DEBUG" help:"Enable debug logging"`

	Version kong.VersionFlag `help:"Print version information"`

	ConfigFile      kong.NamedFileContentFlag `name:"config" required:"" env:"IDP_CONFIG_FILE" help:"Path to the config file."`
	AdminSocketPath string                    `env:"IDP_ADMIN_SOCKET_PATH" help:"Path to Unix socket to serve the admin API (optional for serve)."`

	Serve             idp.ServeCmd                  `cmd:"" help:"Serve the IDP server."`
	ValidateConfig    ValidateConfigCmd             `cmd:"" help:"Validate the configuration file."`
	AddCredential     admincli.AddCredentialCmd     `cmd:"" help:"Add a credential to a user."`
	ConfirmCredential admincli.ConfirmCredentialCmd `cmd:"" help:"Confirm a pending credential enrollment."`
	ListCredentials   admincli.ListCredentialsCmd   `cmd:"" help:"List all credentials."`
	DeleteCredential  admincli.DeleteCredentialCmd  `cmd:"" help:"Delete a credential."`
}{}

type ValidateConfigCmd struct{}

func (c *ValidateConfigCmd) Run() error {
	// Everything is already validated in main
	slog.Info("Configuration and policies are valid")
	return nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
		// Exit immediately on second signal
		<-sigCh
		os.Exit(1)
	}()

	clictx := kong.Parse(
		&rootCmd,
		kong.Description("passidp is a webauthn/oidc identity provider"),
		kong.Vars{"version": promversion.Version},
	)

	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if rootCmd.Debug {
		slogOpts.Level = slog.LevelDebug
	}
	var handler slog.Handler
	if term.IsTerminal(int(os.Stderr.Fd())) {
		handler = slog.NewTextHandler(os.Stderr, slogOpts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, slogOpts)
	}
	slog.SetDefault(slog.New(handler))

	if clictx.Selected().Name != "serve" && clictx.Selected().Name != "validate-config" {
		if rootCmd.AdminSocketPath == "" {
			clictx.Fatalf("admin socket path is required")
		}
	}

	cfg, err := config.ParseConfig(rootCmd.ConfigFile)
	if err != nil {
		clictx.Fatalf("parse config from %s: %v", rootCmd.ConfigFile.Filename, err)
	}

	if err := policy.ValidatePolicies(cfg); err != nil {
		clictx.Fatalf("validate policies: %v", err)
	}

	clictx.Bind(cfg)
	clictx.Bind(adminapi.SocketPath(rootCmd.AdminSocketPath))

	clictx.BindTo(ctx, (*context.Context)(nil))
	clictx.FatalIfErrorf(clictx.Run())
}
