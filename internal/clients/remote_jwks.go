package clients

import (
	"context"
	"log/slog"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwt/remotejwks"
)

const defaultRemoteJWKSRetryInterval = 10 * time.Second

// RemoteJWKS keeps one static client's remote keys loaded. Startup never waits
// on it: until the first fetch succeeds the client's key set is empty, so only
// that client's private_key_jwt authentication fails while its JWKS host is
// unreachable.
type RemoteJWKS struct {
	ClientID string
	URL      string

	keys  *jwt.VerificationKeySet
	retry time.Duration
}

// Run loads the JWKS, retrying until it succeeds, then keeps it fresh. A failed
// refresh keeps the last good keys. Run returns nil when ctx is cancelled.
func (r *RemoteJWKS) Run(ctx context.Context) error {
	log := slog.With(slog.String("client_id", r.ClientID), slog.String("jwks_url", r.URL))
	retry := r.retry
	if retry == 0 {
		retry = defaultRemoteJWKSRetryInterval
	}
	var source *remotejwks.Source
	for {
		var err error
		if source == nil {
			source, err = remotejwks.Open(ctx, remotejwks.Config{URL: r.URL, VerificationKeySet: r.keys})
			if err == nil {
				log.Info("loaded client JWKS")
			}
		}
		if source != nil {
			err = source.Run(ctx)
		}
		if ctx.Err() != nil {
			return nil
		}
		if source == nil {
			log.Error("client JWKS not loaded; private_key_jwt authentication for this client fails until it is", slog.String("error", err.Error()))
		} else {
			log.Error("refresh client JWKS failed; retaining last good keys", slog.String("error", err.Error()))
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
