package storage_test

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/passkey"
	"github.com/descope/virtualwebauthn"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

func TestPasskeyRecordFromLegacyCredential(t *testing.T) {
	env := registerLegacyFixture(t)

	t.Run("authenticator_data", func(t *testing.T) {
		cred := &storage.Credential{
			ID:             uuid.New(),
			UserID:         env.accountID,
			Name:           "authdata",
			CredentialData: env.blobWith(legacyBlob{authenticatorData: env.authData, transports: env.transports}),
		}
		got, err := storage.PasskeyRecordFromLegacyCredential(cred, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != env.record {
			t.Fatalf("record mismatch\n got %s\nwant %s", got, env.record)
		}
	})

	t.Run("attestation_object", func(t *testing.T) {
		if len(env.attestationObject) == 0 {
			t.Fatal("fixture missing attestation object")
		}
		cred := &storage.Credential{
			CredentialData: env.blobWith(legacyBlob{attestationObject: env.attestationObject, transports: env.transports}),
		}
		got, err := storage.PasskeyRecordFromLegacyCredential(cred, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != env.record {
			t.Fatalf("record mismatch\n got %s\nwant %s", got, env.record)
		}
	})

	t.Run("synthesized", func(t *testing.T) {
		fields := parseAuthData(t, env.authData)
		cred := &storage.Credential{
			CredentialID: fields.id,
			CredentialData: env.blobWith(legacyBlob{
				id:             fields.id,
				publicKey:      fields.publicKey,
				transports:     env.transports,
				userPresent:    fields.userPresent,
				userVerified:   fields.userVerified,
				backupEligible: fields.backupEligible,
				backupState:    fields.backupState,
				aaguid:         fields.aaguid,
				signCount:      fields.signCount,
			}),
		}
		got, err := storage.PasskeyRecordFromLegacyCredential(cred, env.rpID)
		if err != nil {
			t.Fatal(err)
		}
		if got != env.record {
			t.Fatalf("record mismatch\n got %s\nwant %s", got, env.record)
		}
	})

	t.Run("synthesized_zero_flags", func(t *testing.T) {
		fields := parseAuthData(t, env.authData)
		cred := &storage.Credential{
			CredentialData: env.blobWith(legacyBlob{
				id:         fields.id,
				publicKey:  fields.publicKey,
				aaguid:     fields.aaguid,
				signCount:  39,
				transports: []string{},
			}),
		}
		got, err := storage.PasskeyRecordFromLegacyCredential(cred, env.rpID)
		if err != nil {
			t.Fatal(err)
		}
		normalized := parseAuthData(t, authDataFromRecord(t, got))
		if !normalized.userPresent || !normalized.userVerified {
			t.Fatalf("synthesized zero-flag record flags = UP:%t UV:%t, want both normalized on", normalized.userPresent, normalized.userVerified)
		}
	})

	t.Run("empty_attestation_strings", func(t *testing.T) {
		fields := parseAuthData(t, env.authData)
		raw, err := json.Marshal(map[string]any{
			"id":        fields.id,
			"publicKey": fields.publicKey,
			"transport": []string{},
			"flags": map[string]bool{
				"userPresent":    true,
				"userVerified":   true,
				"backupEligible": true,
				"backupState":    true,
			},
			"authenticator": map[string]any{
				"AAGUID":    fields.aaguid,
				"signCount": 0,
			},
			"attestation": map[string]any{
				"clientDataJSON":     "",
				"clientDataHash":     "",
				"authenticatorData":  "",
				"publicKeyAlgorithm": 0,
				"object":             "",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := storage.PasskeyRecordFromLegacyCredential(&storage.Credential{CredentialData: raw}, env.rpID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := passkey.AAGUID(got); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing_data", func(t *testing.T) {
		_, err := storage.PasskeyRecordFromLegacyCredential(&storage.Credential{Name: "empty"}, "localhost")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestApplyConfigImportsLegacyCredentials(t *testing.T) {
	env := registerLegacyFixture(t)
	path := t.TempDir() + "/credentials.json"
	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}

	legacyID := uuid.New()
	unconvertibleID := uuid.New()
	if err := store.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials,
			&storage.Credential{
				ID:             legacyID,
				UserID:         env.accountID,
				Name:           "old-key",
				CredentialData: env.blobWith(legacyBlob{authenticatorData: env.authData, transports: env.transports}),
				CreatedAt:      time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			},
			&storage.Credential{
				ID:     unconvertibleID,
				UserID: env.accountID,
				Name:   "broken",
			},
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	users := config.Users{{
		ID:             env.accountID,
		WebauthnHandle: uuid.New(),
	}}
	if err := store.ApplyConfig(users, env.rpID); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyConfig(users, env.rpID); err != nil {
		t.Fatal(err)
	}

	store.Read(func(cs *storage.CredentialStore) {
		if len(cs.Credentials) != 1 || cs.Credentials[0].ID != unconvertibleID {
			t.Fatalf("want only unconvertible leftover, got %+v", cs.Credentials)
		}
		records := cs.PasskeyRecords(env.accountID)
		if len(records) != 1 || records[0] != env.record {
			t.Fatalf("PasskeyRecords = %q, want %q", records, env.record)
		}
		listed := cs.UserCredentials(env.accountID)
		if len(listed) != 2 {
			t.Fatalf("UserCredentials = %d, want 2", len(listed))
		}
		var imported *storage.Passkey
		for _, pk := range cs.Users[0].Passkeys {
			if pk.ID == legacyID {
				imported = pk
			}
		}
		if imported == nil || imported.Name != "old-key" || imported.Record != env.record {
			t.Fatalf("imported passkey = %+v", imported)
		}
	})
}

type legacyBlob struct {
	id                []byte
	publicKey         []byte
	transports        []string
	userPresent       bool
	userVerified      bool
	backupEligible    bool
	backupState       bool
	aaguid            []byte
	signCount         uint32
	authenticatorData []byte
	attestationObject []byte
}

func (env legacyFixture) blobWith(b legacyBlob) json.RawMessage {
	raw, err := json.Marshal(struct {
		ID        []byte   `json:"id,omitempty"`
		PublicKey []byte   `json:"publicKey,omitempty"`
		Transport []string `json:"transport,omitempty"`
		Flags     struct {
			UserPresent    bool `json:"userPresent"`
			UserVerified   bool `json:"userVerified"`
			BackupEligible bool `json:"backupEligible"`
			BackupState    bool `json:"backupState"`
		} `json:"flags"`
		Authenticator struct {
			AAGUID    []byte `json:"AAGUID,omitempty"`
			SignCount uint32 `json:"signCount,omitempty"`
		} `json:"authenticator"`
		Attestation struct {
			AuthenticatorData []byte `json:"authenticatorData,omitempty"`
			Object            []byte `json:"object,omitempty"`
		} `json:"attestation"`
	}{
		ID:        b.id,
		PublicKey: b.publicKey,
		Transport: b.transports,
		Flags: struct {
			UserPresent    bool `json:"userPresent"`
			UserVerified   bool `json:"userVerified"`
			BackupEligible bool `json:"backupEligible"`
			BackupState    bool `json:"backupState"`
		}{
			UserPresent:    b.userPresent,
			UserVerified:   b.userVerified,
			BackupEligible: b.backupEligible,
			BackupState:    b.backupState,
		},
		Authenticator: struct {
			AAGUID    []byte `json:"AAGUID,omitempty"`
			SignCount uint32 `json:"signCount,omitempty"`
		}{
			AAGUID:    b.aaguid,
			SignCount: b.signCount,
		},
		Attestation: struct {
			AuthenticatorData []byte `json:"authenticatorData,omitempty"`
			Object            []byte `json:"object,omitempty"`
		}{
			AuthenticatorData: b.authenticatorData,
			Object:            b.attestationObject,
		},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

type legacyFixture struct {
	rpID              string
	accountID         uuid.UUID
	record            string
	authData          []byte
	attestationObject []byte
	transports        []string
}

func registerLegacyFixture(t *testing.T) legacyFixture {
	t.Helper()
	const rpID = "test.example.com"
	rp, err := passkey.NewRelyingParty(rpID, "https://example.com", passkey.Options{})
	if err != nil {
		t.Fatal(err)
	}

	passkeyUserID := "legacy-import-user"
	optionsJSON, err := rp.NewRegistration(passkey.User{ID: passkeyUserID, Name: "legacy@example.com"}, passkey.RegistrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatal(err)
	}

	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = []byte(passkeyUserID)
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(credential)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		virtualwebauthn.RelyingParty{ID: rpID, Name: "Test", Origin: "https://example.com"},
		authenticator,
		credential,
		*attestationOptions,
	)

	record, err := rp.Register([]byte(attestationResponse))
	if err != nil {
		t.Fatal(err)
	}

	var resp struct {
		Response struct {
			AuthenticatorData string   `json:"authenticatorData"`
			AttestationObject string   `json:"attestationObject"`
			Transports        []string `json:"transports"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(attestationResponse), &resp); err != nil {
		t.Fatal(err)
	}
	attObj, err := base64.RawURLEncoding.DecodeString(resp.Response.AttestationObject)
	if err != nil {
		t.Fatal(err)
	}

	return legacyFixture{
		rpID:              rpID,
		accountID:         uuid.New(),
		record:            record,
		authData:          authDataFromRecord(t, record),
		attestationObject: attObj,
		transports:        resp.Response.Transports,
	}
}

func authDataFromRecord(t *testing.T, record string) []byte {
	t.Helper()
	rest, ok := strings.CutPrefix(record, "$webauthn$v=1$")
	if !ok {
		t.Fatalf("not a passkey record: %s", record)
	}
	if _, payload, found := strings.Cut(rest, "$"); found {
		rest = payload
	}
	ad, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil {
		t.Fatal(err)
	}
	if len(ad) == 0 {
		t.Fatal("empty authenticator data in record")
	}
	return ad
}

type parsedAuthData struct {
	id             []byte
	publicKey      []byte
	aaguid         []byte
	signCount      uint32
	userPresent    bool
	userVerified   bool
	backupEligible bool
	backupState    bool
}

func parseAuthData(t *testing.T, ad []byte) parsedAuthData {
	t.Helper()
	if len(ad) < 55 {
		t.Fatalf("authData too short: %d", len(ad))
	}
	flags := ad[32]
	credLen := binary.BigEndian.Uint16(ad[53:55])
	idStart := 55
	idEnd := idStart + int(credLen)
	if len(ad) < idEnd {
		t.Fatalf("authData too short for credential ID")
	}
	return parsedAuthData{
		id:             ad[idStart:idEnd],
		publicKey:      ad[idEnd:],
		aaguid:         ad[37:53],
		signCount:      binary.BigEndian.Uint32(ad[33:37]),
		userPresent:    flags&(1<<0) != 0,
		userVerified:   flags&(1<<2) != 0,
		backupEligible: flags&(1<<3) != 0,
		backupState:    flags&(1<<4) != 0,
	}
}
