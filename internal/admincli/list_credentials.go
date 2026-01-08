package admincli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"text/tabwriter"

	"lds.li/webauthn-oidc-idp/internal/config"
)

type ListCredentialsCmd struct {
	SocketPath string `required:"" env:"IDP_ADMIN_SOCKET_PATH" help:"Path to admin API Unix socket."`

	Output io.Writer `kong:"-"`
}

type listCredentialsResponse struct {
	Credentials []credentialInfo `json:"credentials"`
}

type credentialInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UserID    string `json:"user_id"`
	UserName  string `json:"user_name"`
	UserEmail string `json:"user_email"`
	CreatedAt string `json:"created_at"`
}

func (c *ListCredentialsCmd) Run(ctx context.Context, cfg *config.Config) error {
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

	req, err := http.NewRequestWithContext(ctx, "GET", "http://unix/admin/credentials", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var listResp listCredentialsResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(listResp.Credentials) == 0 {
		fmt.Fprintf(c.Output, "No credentials found.\n")
		return nil
	}

	w := tabwriter.NewWriter(c.Output, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tName\tUser ID\tUser Name\tUser Email\tCreated At\n")
	for _, cred := range listResp.Credentials {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cred.ID,
			cred.Name,
			cred.UserID,
			cred.UserName,
			cred.UserEmail,
			cred.CreatedAt,
		)
	}
	return w.Flush()
}
