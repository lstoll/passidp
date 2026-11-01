// Package oauth2as implements the OAuth 2.0 / OpenID Connect authorization
// server used by passidp
// (https://openid.net/specs/openid-connect-core-1_0.html). Persistent state is
// stored in SQLite via [NewSQLStorage].
// Note: It does not _enforce_ all behaviours required by the spec,
// callers should be sure to not introduce non-compliant behaviours.
package oauth2as
