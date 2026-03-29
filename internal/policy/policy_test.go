package policy

import (
	"testing"

	"github.com/google/uuid"
	"lds.li/passidp/claims"
	"lds.li/passidp/internal/config"
)

func TestPolicyEvaluator_EvaluateAuthorization(t *testing.T) {
	pe, err := NewPolicyEvaluator()
	if err != nil {
		t.Fatalf("NewPolicyEvaluator() error = %v", err)
	}

	user := &config.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		FullName: "Test User",
		Groups:   []string{"group1", "group2"},
	}

	tests := []struct {
		name       string
		expression string
		want       bool
		wantErr    bool
	}{
		{
			name:       "empty expression",
			expression: "",
			want:       true,
		},
		{
			name:       "simple true",
			expression: "true",
			want:       true,
		},
		{
			name:       "simple false",
			expression: "false",
			want:       false,
		},
		{
			name:       "check group",
			expression: "'group1' in user.groups",
			want:       true,
		},
		{
			name:       "check missing group",
			expression: "'group3' in user.groups",
			want:       false,
		},
		{
			name:       "check email",
			expression: "user.email == 'test@example.com'",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pe.EvaluateAuthorization(tt.expression, user)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateAuthorization() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EvaluateAuthorization() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyEvaluator_EvaluateClaims(t *testing.T) {
	pe, err := NewPolicyEvaluator()
	if err != nil {
		t.Fatalf("NewPolicyEvaluator() error = %v", err)
	}

	user := &config.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		FullName: "Test User",
		Metadata: map[string]any{
			"overrideSubject": "overridden",
		},
	}

	initialClaims := &claims.IDClaims{}
	initialClaims.SetSubject("original")
	initialClaims.SetEmail("test@example.com")

	tests := []struct {
		name       string
		expression string
		wantSubject string
		wantErr    bool
	}{
		{
			name:       "empty expression",
			expression: "",
			wantSubject: "original",
		},
		{
			name:       "override subject",
			expression: "has(user.metadata.overrideSubject) ? claims.patch({ 'sub': user.metadata.overrideSubject }) : claims",
			wantSubject: "overridden",
		},
		{
			name:       "clear email",
			expression: "claims.patch({ 'email': null })",
			wantSubject: "original",
		},
		{
			name:       "invalid field",
			expression: "claims.patch({ 'nonexistent': 'value' })",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pe.EvaluateClaims(tt.expression, initialClaims, user)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.GetSubject() != tt.wantSubject {
				t.Errorf("EvaluateClaims() got subject = %v, want %v", got.GetSubject(), tt.wantSubject)
			}
			if !tt.wantErr && tt.name == "clear email" && got.HasEmail() {
				t.Errorf("EvaluateClaims() email should be cleared")
			}
		})
	}
}
