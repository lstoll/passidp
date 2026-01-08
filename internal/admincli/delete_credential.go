package admincli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"lds.li/passidp/internal/config"
)

type DeleteCredentialCmd struct {
	CredentialID string `required:"" help:"ID of the credential to delete."`
	SocketPath   string `required:"" env:"IDP_ADMIN_SOCKET_PATH" help:"Path to admin API Unix socket."`

	Output io.Writer `kong:"-"`
}

func (c *DeleteCredentialCmd) Run(ctx context.Context, cfg *config.Config) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", c.SocketPath)
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("http://unix/admin/credentials/%s", c.CredentialID), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
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
