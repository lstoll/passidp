package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"lds.li/passidp/internal/storage/dbsql"
)

var (
	// ErrDynamicClientNotFound is returned when a dynamic client is not found.
	ErrDynamicClientNotFound = errors.New("dynamic client not found")
)

// DynamicClientStore persists dynamically registered OIDC clients in SQLite.
type DynamicClientStore struct {
	queries *dbsql.Queries
}

// DynamicClient is a dynamically registered OIDC client.
type DynamicClient struct {
	ID               string
	Active           bool
	ExpiresAt        time.Time
	CreatedAt        time.Time
	ClientSecret     string
	RegistrationBlob json.RawMessage
}

// NewDynamicClientStore returns a SQL-backed dynamic client store.
func NewDynamicClientStore(sqlDB *sql.DB) *DynamicClientStore {
	return &DynamicClientStore{queries: dbsql.New(sqlDB)}
}

func (s *DynamicClientStore) GetDynamicClient(ctx context.Context, id string) (DynamicClient, error) {
	row, err := s.getDynamicClientRow(ctx, id)
	if err != nil {
		return DynamicClient{}, err
	}
	if !row.Active || time.Now().After(row.ExpiresAt) {
		return DynamicClient{}, ErrDynamicClientNotFound
	}
	return row, nil
}

func (s *DynamicClientStore) CreateDynamicClient(ctx context.Context, id, clientSecret, registrationBlob string, expiresAt time.Time) error {
	_, err := s.getDynamicClientRow(ctx, id)
	if err == nil {
		return fmt.Errorf("client %s already exists", id)
	}
	if !errors.Is(err, ErrDynamicClientNotFound) {
		return fmt.Errorf("check existing client: %w", err)
	}

	err = s.queries.CreateDynamicClient(ctx, dbsql.CreateDynamicClientParams{
		ID: id, Active: true, ExpiresAt: expiresAt, CreatedAt: time.Now(),
		ClientSecret: clientSecret, RegistrationBlob: registrationBlob,
	})
	return err
}

func (s *DynamicClientStore) DeactivateDynamicClient(ctx context.Context, id string) error {
	if _, err := s.getDynamicClientRow(ctx, id); err != nil {
		return err
	}

	return s.queries.DeactivateDynamicClient(ctx, id)
}

func (s *DynamicClientStore) ListActiveDynamicClients(ctx context.Context) ([]DynamicClient, error) {
	rows, err := s.queries.ListActiveDynamicClients(ctx, time.Now())
	if err != nil {
		return nil, fmt.Errorf("list active dynamic clients: %w", err)
	}
	var clients []DynamicClient
	for _, row := range rows {
		clients = append(clients, convertDynamicClient(row))
	}
	return clients, nil
}

func (s *DynamicClientStore) CleanupExpiredDynamicClients() (int, error) {
	deleted, err := s.queries.CleanupExpiredDynamicClients(context.Background(), time.Now())
	if err != nil {
		return 0, fmt.Errorf("delete expired dynamic clients: %w", err)
	}
	return int(deleted), nil
}

func (s *DynamicClientStore) getDynamicClientRow(ctx context.Context, id string) (DynamicClient, error) {
	row, err := s.queries.GetDynamicClientByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DynamicClient{}, ErrDynamicClientNotFound
		}
		return DynamicClient{}, fmt.Errorf("get dynamic client: %w", err)
	}
	return convertDynamicClient(row), nil
}

func convertDynamicClient(row dbsql.DynamicClient) DynamicClient {
	return DynamicClient{ID: row.ID, Active: row.Active, ExpiresAt: row.ExpiresAt,
		CreatedAt: row.CreatedAt, ClientSecret: row.ClientSecret,
		RegistrationBlob: json.RawMessage(row.RegistrationBlob)}
}
