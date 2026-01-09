package admincli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"lds.li/passidp/internal/adminapi"
)

type DeleteCredentialCmd struct {
	CredentialID string `required:"" help:"ID of the credential to delete."`

	Output io.Writer `kong:"-"`
}

func (c *DeleteCredentialCmd) Run(ctx context.Context, adminSocket adminapi.SocketPath) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("http://unix/admin/credentials/%s", c.CredentialID), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := adminapi.NewClient(adminSocket).Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("credential not found")
	}

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Fprintf(c.Output, "Credential deleted successfully.\n")
	return nil
}
