package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

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
