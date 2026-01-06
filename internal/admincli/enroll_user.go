package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

type EnrollUserCmd struct {
	Email    string `required:"" help:"Email address for the user."`
	FullName string `required:"" help:"Full name of the user."`

	Output io.Writer `kong:"-"`
}

func (c *EnrollUserCmd) Run(ctx context.Context, db *sql.DB, config *config.Config) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	params := queries.CreateUserParams{
		ID:             uuid.Must(uuid.NewV7()),
		Email:          c.Email,
		FullName:       c.FullName,
		EnrollmentKey:  sql.NullString{String: uuid.NewString(), Valid: true},
		WebauthnHandle: uuid.Must(uuid.NewRandom()),
	}

	if err := queries.New(db).CreateUser(ctx, params); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	fmt.Fprintf(c.Output, "New user created: %s\n", params.ID)
	fmt.Fprintf(c.Output, "Enrollment URL: %s\n", fmt.Sprintf("%s/registration?enrollment_token=%s&user_id=%s", config.Issuer, params.EnrollmentKey.String, params.ID))
	return nil
}
