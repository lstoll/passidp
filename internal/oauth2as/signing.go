package oauth2as

// signingInput keeps protocol-selected type and claims together until the
// server-owned jwt.Signer serializes and signs them.
type signingInput struct {
	Type   string
	Claims map[string]any
}
