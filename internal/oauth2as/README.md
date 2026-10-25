# oauth2as

[![Go Reference](https://pkg.go.dev/badge/lds.li/oauth2ext/oauth2as.svg)](https://pkg.go.dev/lds.li/oauth2ext/oauth2as)

Go library for implementing Oauth2/OIDC OPs (Servers). In active development

## Storage

Production servers use sealed SQL storage backed by `database/sql`. The library
does not import a database driver:

```go
store, err := oauth2as.NewSQLStorage(db, oauth2as.SQLStorageOptions{
	Dialect: oauth2as.SQLDialectPostgreSQL,
})
if err != nil {
	return err
}
if err := store.Migrate(ctx); err != nil {
	return err
}
```

Table names default to the `oauth2as_` prefix. Set `TablePrefix` when multiple
independent installations share one database. Each prefix must be dedicated to
one issuer. PostgreSQL deployments may select a schema through `search_path`.

Applications own the `*sql.DB`, must call `Migrate` before serving traffic, and
should periodically call `store.Cleanup` to physically remove expired records.
`NewMemoryStorage` is available for tests and local examples.


## Example

Start the server

```
go run ./cmd/oidc-example-op
```

Request some tokens

```

```
