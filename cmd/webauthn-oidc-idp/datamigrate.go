package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/queries"
	"lds.li/webauthn-oidc-idp/internal/storage"
)

func isMigrationRequired(ctx context.Context, cfg *config.Config) bool {
	return len(cfg.Users) == 0
}

func migrateUserData(ctx context.Context, db *sql.DB, cfg *config.Config) error {
	if len(cfg.Users) > 0 {
		// all good, no action needed.
		return nil
	}

	q := queries.New(db)

	users, err := q.GetUsersForMigration(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	if len(users) == 0 {
		return errors.New("no users found in config or database")
	}

	for _, u := range users {
		groups, err := q.GetUserActiveGroupMembershipsForMigration(ctx, u.ID.String())
		if err != nil {
			return fmt.Errorf("get user active group memberships: %w", err)
		}
		groupNames := make([]string, len(groups))
		for i, g := range groups {
			groupNames[i] = g.GroupName
		}
		cfg.Users = append(cfg.Users, &config.User{
			ID:              u.ID,
			Email:           u.Email,
			FullName:        u.FullName,
			OverrideSubject: u.OverrideSubject.String,
			WebauthnHandle:  u.WebauthnHandle,
			Groups:          groupNames,
		})
	}

	slog.WarnContext(ctx, "no users in config file. Using the database, please add the following to config ASAP")

	jsonData, err := json.MarshalIndent(cfg.Users, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", jsonData)

	return nil
}

func migrateCredentials(ctx context.Context, db *sql.DB, path string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		// ignore, let the migration go.
	} else if err != nil {
		return fmt.Errorf("stat credential store: %w", err)
	} else {
		// store exists, all good.
		return nil
	}

	store, err := storage.NewCredentialStore(path)
	if err != nil {
		return fmt.Errorf("new credential store: %w", err)
	}

	q := queries.New(db)
	credentials, err := q.GetCredentialsForMigration(ctx)
	if err != nil {
		return fmt.Errorf("get credentials for migration: %w", err)
	}

	if err := store.Write(func(cs *storage.CredentialStore) error {
		for _, c := range credentials {
			var credData *webauthn.Credential
			if err := json.Unmarshal(c.CredentialData, &credData); err != nil {
				return fmt.Errorf("unmarshal credential data: %w", err)
			}

			cs.Credentials = append(cs.Credentials, &storage.Credential{
				ID:             c.ID,
				CredentialID:   c.CredentialID,
				UserID:         c.UserID,
				Name:           c.Name,
				CredentialData: credData,
				CreatedAt:      c.CreatedAt,
			})
		}
		return nil
	}); err != nil {
		return fmt.Errorf("write credential store: %w", err)
	}

	return nil
}
