package admincli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"lds.li/passidp/internal/config"
)

type ConfirmCredentialCmd struct {
	UserID          string `required:"" help:"ID of user the credential belongs to."`
	EnrollmentID    string `required:"" help:"ID of the enrollment to confirm."`
	ConfirmationKey string `required:"" help:"Confirmation key from the enrollment."`
	SocketPath      string `required:"" env:"IDP_ADMIN_SOCKET_PATH" help:"Path to admin API Unix socket."`

	Output io.Writer `kong:"-"`
}

type confirmEnrollmentRequest struct {
	UserID          string `json:"user_id"`
	EnrollmentID    string `json:"enrollment_id"`
	ConfirmationKey string `json:"confirmation_key"`
}

type confirmEnrollmentResponse struct {
	Name   string `json:"name"`
	UserID string `json:"user_id"`
}

func (c *ConfirmCredentialCmd) Run(ctx context.Context, cfg *config.Config) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	reqBody := confirmEnrollmentRequest{
		UserID:          c.UserID,
		EnrollmentID:    c.EnrollmentID,
		ConfirmationKey: c.ConfirmationKey,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", c.SocketPath)
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "http://unix/admin/enrollments/confirm", bytes.NewReader(reqJSON))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var confirmResp confirmEnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&confirmResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	fmt.Fprintf(c.Output, "Credential confirmed and activated successfully!\n")
	fmt.Fprintf(c.Output, "Name: %s\n", confirmResp.Name)
	fmt.Fprintf(c.Output, "User ID: %s\n", confirmResp.UserID)
	return nil
}
