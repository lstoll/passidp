package adminapi

import (
	"context"
	"net"
	"net/http"
)

// SocketPath is the type we pass the socket path around in, for binding.
type SocketPath string

// NewClient creates a new http.Client that can talk to the admin API over a
// Unix socket located at socketPath.
func NewClient(socketPath SocketPath) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", string(socketPath))
			},
		},
	}
}
