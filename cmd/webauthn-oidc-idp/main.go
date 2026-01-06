package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/alecthomas/kong"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	promversion "github.com/prometheus/common/version"
	"golang.org/x/term"
	dbpkg "lds.li/webauthn-oidc-idp/db"
	"lds.li/webauthn-oidc-idp/internal/admincli"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/idp"
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

	ConfigFile kong.NamedFileContentFlag `name:"config" required:"" env:"IDP_CONFIG_FILE" help:"Path to the config file."`
	DBPath     string                    `required:"" env:"IDP_DB_PATH" help:"Path to the SQLite database file."`

	Version kong.VersionFlag `help:"Print version information"`

	Serve         idp.ServeCmd              `cmd:"" help:"Serve the IDP server."`
	AddCredential admincli.AddCredentialCmd `cmd:"" help:"Add a credential to a user."`
}{}

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
		kong.Description("webauthn-oidc-idp is a webauthn/oidc identity provider"),
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

	config, err := config.ParseConfig(rootCmd.ConfigFile.Contents)
	if err != nil {
		slog.Error("parse config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	var db *sql.DB
	{ // set up DB
		var err error
		db, err = sql.Open("sqlite3", rootCmd.DBPath+"?_journal=WAL")
		if err != nil {
			slog.Error("open database", slog.String("path", rootCmd.DBPath), slog.String("error", err.Error()))
			os.Exit(1)
		}

		if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			slog.Error("enable WAL mode", slog.String("error", err.Error()))
			os.Exit(1)
		}

		if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
			slog.Error("set busy timeout", slog.String("error", err.Error()))
			os.Exit(1)
		}

		if err := dbpkg.Migrate(ctx, db); err != nil {
			slog.Error("run migrations", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	// run any data migrations
	if err := migrateUserData(ctx, db, config); err != nil {
		slog.Error("migrate user data", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if clictx.Selected().Name == "serve" {
		if err := migrateCredentials(ctx, db, rootCmd.Serve.CredentialStorePath); err != nil {
			slog.Error("migrate credentials", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	clictx.BindTo(ctx, (*context.Context)(nil))
	clictx.Bind(config)
	clictx.FatalIfErrorf(clictx.Run())
}
