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

	"lds.li/webauthn-oidc-idp/internal/config"
)

type AddCredentialCmd struct {
	UserID     string `required:"" help:"ID of user to add credential to."`
	SocketPath string `required:"" env:"IDP_ADMIN_SOCKET_PATH" help:"Path to admin API Unix socket."`

	Output io.Writer `kong:"-"`
}

type createEnrollmentRequest struct {
	UserID string `json:"user_id"`
}

type createEnrollmentResponse struct {
	EnrollmentID  string `json:"enrollment_id"`
	EnrollmentKey string `json:"enrollment_key"`
	EnrollmentURL string `json:"enrollment_url"`
}

func (c *AddCredentialCmd) Run(ctx context.Context, cfg *config.Config) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	reqBody := createEnrollmentRequest{
		UserID: c.UserID,
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

	req, err := http.NewRequestWithContext(ctx, "POST", "http://unix/admin/enrollments", bytes.NewReader(reqJSON))
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

	var enrollmentResp createEnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollmentResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	fmt.Fprintf(c.Output, "Enrollment ID: %s\n", enrollmentResp.EnrollmentID)
	fmt.Fprintf(c.Output, "Enrollment Key: %s\n", enrollmentResp.EnrollmentKey)
	fmt.Fprintf(c.Output, "Enroll at: %s\n", enrollmentResp.EnrollmentURL)
	return nil
}
