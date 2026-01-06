package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/google/uuid"
	"github.com/oklog/run"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/storage"
)

// Server provides an admin API over a Unix socket.
type Server struct {
	state      *storage.State
	config     *config.Config
	credStore  *jsonfile.JSONFile[storage.CredentialStore]
	socketPath string
}

// NewServer creates a new admin API server.
func NewServer(state *storage.State, cfg *config.Config, credStore *jsonfile.JSONFile[storage.CredentialStore], socketPath string) *Server {
	return &Server{
		state:      state,
		config:     cfg,
		credStore:  credStore,
		socketPath: socketPath,
	}
}

// Start starts the admin API server on a Unix socket.
func (s *Server) Start(ctx context.Context, g *run.Group) error {
	// Remove socket if it exists
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove existing socket: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}

	// Set socket permissions to 0600 (owner read/write only)
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		return fmt.Errorf("set socket permissions: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/enrollments", s.handleCreateEnrollment)
	mux.HandleFunc("/admin/enrollments/confirm", s.handleConfirmEnrollment)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	g.Add(func() error {
		slog.Info("admin API server listening", slog.String("socket", s.socketPath))
		return server.Serve(listener)
	}, func(error) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
		_ = os.Remove(s.socketPath)
	})

	return nil
}

type CreateEnrollmentRequest struct {
	UserID string `json:"user_id"`
}

type CreateEnrollmentResponse struct {
	EnrollmentID  string `json:"enrollment_id"`
	EnrollmentKey string `json:"enrollment_key"`
	EnrollmentURL string `json:"enrollment_url"`
}

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode request: %v", err), http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid user_id: %v", err), http.StatusBadRequest)
		return
	}

	// Verify user exists
	_, err = s.config.Users.GetUser(userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("user not found: %v", err), http.StatusNotFound)
		return
	}

	enrollment, err := s.state.CreatePendingEnrollment(userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("create enrollment: %v", err), http.StatusInternalServerError)
		return
	}

	enrollmentURL := fmt.Sprintf("%s/registration?enrollment_token=%s&user_id=%s",
		s.config.Issuer, enrollment.EnrollmentKey, userID.String())

	resp := CreateEnrollmentResponse{
		EnrollmentID:  enrollment.ID.String(),
		EnrollmentKey: enrollment.EnrollmentKey,
		EnrollmentURL: enrollmentURL,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("encode response", slog.String("error", err.Error()))
	}
}

type ConfirmEnrollmentRequest struct {
	UserID         string `json:"user_id"`
	EnrollmentID   string `json:"enrollment_id"`
	ConfirmationKey string `json:"confirmation_key"`
}

type ConfirmEnrollmentResponse struct {
	Name   string `json:"name"`
	UserID string `json:"user_id"`
}

func (s *Server) handleConfirmEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ConfirmEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode request: %v", err), http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid user_id: %v", err), http.StatusBadRequest)
		return
	}

	enrollmentID, err := uuid.Parse(req.EnrollmentID)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid enrollment_id: %v", err), http.StatusBadRequest)
		return
	}

	enrollment, err := s.state.ConfirmPendingEnrollment(enrollmentID, req.ConfirmationKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("confirm enrollment: %v", err), http.StatusBadRequest)
		return
	}

	if enrollment.UserID != userID {
		http.Error(w, "enrollment user_id mismatch", http.StatusBadRequest)
		return
	}

	// Write credential to the credential store
	if err := s.credStore.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{
			ID:             uuid.New(),
			CredentialID:   enrollment.CredentialID,
			CredentialData: enrollment.CredentialData,
			Name:           enrollment.Name,
			UserID:         enrollment.UserID,
		})
		return nil
	}); err != nil {
		http.Error(w, fmt.Sprintf("write credential: %v", err), http.StatusInternalServerError)
		return
	}

	resp := ConfirmEnrollmentResponse{
		Name:   enrollment.Name,
		UserID: enrollment.UserID.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("encode response", slog.String("error", err.Error()))
	}
}
