package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/alecthomas/kong"
	"go.etcd.io/bbolt"
)

var rootCmd = struct {
	StateFile string `name:"state-file" required:""  help:"Path to the state file."`

	ListBuckets        ListBucketsCmd        `cmd:"" help:"List all buckets."`
	ListBucketContents ListBucketContentsCmd `cmd:"" help:"List all items in a bucket."`
}{}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
		// Exit immediately on second signal
		<-sigCh
		os.Exit(1)
	}()

	clictx := kong.Parse(
		&rootCmd,
		kong.Description("passidp-store is a tool to query the state database"),
	)

	clictx.BindTo(ctx, (*context.Context)(nil))

	clictx.FatalIfErrorf(clictx.Run())
}

type ListBucketsCmd struct {
}

func (c *ListBucketsCmd) Run(ctx context.Context) error {
	db, err := bbolt.Open(rootCmd.StateFile, 0o600, nil)
	if err != nil {
		return fmt.Errorf("open state file: %w", err)
	}
	defer db.Close()

	return db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bbolt.Bucket) error {
			fmt.Println(string(name))
			return nil
		})
	})
}

type ListBucketContentsCmd struct {
	Bucket string `arg:"" required:"" help:"Bucket name to list contents of."`
}

func (c *ListBucketContentsCmd) Run(ctx context.Context) error {
	db, err := bbolt.Open(rootCmd.StateFile, 0o600, nil)
	if err != nil {
		return fmt.Errorf("open state file: %w", err)
	}
	defer db.Close()

	type bucketItem struct {
		key   string
		value []byte
		exp   time.Time
	}

	var items []bucketItem
	err = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(c.Bucket))
		if b == nil {
			return fmt.Errorf("bucket %q does not exist", c.Bucket)
		}
		return b.ForEach(func(k, v []byte) error {
			item := bucketItem{key: string(k), value: append([]byte(nil), v...)}
			// Try to parse as JSON and extract expiry
			if exp := extractExpiryFromJSON(v); !exp.IsZero() {
				item.exp = exp
			}
			items = append(items, item)
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Sort by expiry if we have any expiry data
	hasExpiry := false
	for _, item := range items {
		if !item.exp.IsZero() {
			hasExpiry = true
			break
		}
	}
	if hasExpiry {
		sort.Slice(items, func(i, j int) bool {
			ei, ej := items[i].exp, items[j].exp
			if ei.IsZero() && ej.IsZero() {
				return items[i].key < items[j].key
			}
			if ei.IsZero() {
				return false // zero expiry sorts last
			}
			if ej.IsZero() {
				return true
			}
			return ei.Before(ej) // oldest first
		})
	} else {
		sort.Slice(items, func(i, j int) bool {
			return items[i].key < items[j].key
		})
	}

	for _, item := range items {
		fmt.Printf("--- %s ---\n", item.key)
		if !item.exp.IsZero() {
			fmt.Printf("expires: %s\n", item.exp.Format(time.RFC3339))
		}
		fmt.Printf("%s\n\n", string(item.value))
	}
	return nil
}

// extractExpiryFromJSON parses v as JSON and returns expiresAt or expires_at if present.
func extractExpiryFromJSON(v []byte) time.Time {
	var m map[string]any
	if err := json.Unmarshal(v, &m); err != nil {
		return time.Time{}
	}
	for _, key := range []string{"expiresAt", "expires_at", "storage_expires_at", "storageExpiresAt"} {
		if val, ok := m[key]; ok && val != nil {
			switch t := val.(type) {
			case string:
				parsed, err := time.Parse(time.RFC3339, t)
				if err != nil {
					parsed, err = time.Parse(time.RFC3339Nano, t)
				}
				if err == nil {
					return parsed
				}
			case float64:
				// Unix timestamp in seconds
				return time.Unix(int64(t), 0)
			}
		}
	}
	return time.Time{}
}
