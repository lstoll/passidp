package admincli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"lds.li/webauthn-oidc-idp/internal/config"
)

type AddCredentialCmd struct {
	UserID string `required:"" help:"ID of user to add credential to."`

	Output io.Writer `kong:"-"`
}

func (c *AddCredentialCmd) Run(ctx context.Context, cfg *config.Config) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	userUUID, err := uuid.Parse(c.UserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	user, err := cfg.Users.GetUser(userUUID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// this is temporary, will only exist in memory.

	user.EnrollmentKey = uuid.NewString()

	fmt.Fprintf(c.Output, "Enroll at: %s\n", fmt.Sprintf("%s/registration?enrollment_token=%s&user_id=%s", cfg.Issuer, user.EnrollmentKey, userUUID.String()))
	return nil
}
