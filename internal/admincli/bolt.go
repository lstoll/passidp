package admincli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"lds.li/passidp/internal/adminapi"
)

// DeleteBucketContentsCmd deletes all contents from a specific bucket.
type DeleteBucketContentsCmd struct {
	BucketName string    `arg:"" help:"Name of the bucket to delete contents from."`
	Output     io.Writer `kong:"-"`
}

// BoltCmd is the parent command for bolt-related operations.
type BoltCmd struct {
	ListBuckets          ListBucketsCmd          `cmd:"" help:"List all BoltDB buckets."`
	ListBucketContents   ListBucketContentsCmd   `cmd:"" help:"List contents of a specific bucket."`
	DeleteBucketContents DeleteBucketContentsCmd `cmd:"" help:"Delete all contents from a bucket."`
}

// ListBucketsCmd lists all BoltDB buckets.
type ListBucketsCmd struct {
	Output io.Writer `kong:"-"`
}

type bucketResponse struct {
	Bucket string `json:"bucket"`
}

func (c *ListBucketsCmd) Run(ctx context.Context, adminSocket adminapi.SocketPath) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://unix/admin/boltdb/buckets", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := adminapi.NewClient(adminSocket).Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	// Stream NDJSON response
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var bucket bucketResponse
		if err := json.Unmarshal(line, &bucket); err != nil {
			return fmt.Errorf("decode bucket response: %w", err)
		}

		fmt.Fprintf(c.Output, "%s\n", bucket.Bucket)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}

// ListBucketContentsCmd lists contents of a specific bucket.
type ListBucketContentsCmd struct {
	BucketName string    `arg:"" help:"Name of the bucket to list contents for."`
	Output     io.Writer `kong:"-"`
}

type bucketEntryResponse struct {
	Key      string          `json:"key"`
	KeyParts []string        `json:"key_parts,omitempty"`
	Value    json.RawMessage `json:"value"`
	Format   string          `json:"format"`
}

func (c *ListBucketContentsCmd) Run(ctx context.Context, adminSocket adminapi.SocketPath) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	url := fmt.Sprintf("http://unix/admin/boltdb/buckets/%s", c.BucketName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := adminapi.NewClient(adminSocket).Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	// Stream NDJSON response
	scanner := bufio.NewScanner(resp.Body)
	first := true
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry bucketEntryResponse
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("decode entry response: %w", err)
		}

		if !first {
			fmt.Fprintf(c.Output, "\n")
		}
		first = false

		fmt.Fprintf(c.Output, "Key: %s", entry.Key)
		if len(entry.KeyParts) > 1 {
			fmt.Fprintf(c.Output, "\nKey Parts:")
			for i, part := range entry.KeyParts {
				fmt.Fprintf(c.Output, "\n  [%d] %s", i+1, part)
			}
			fmt.Fprintf(c.Output, "\n")
		}
		if entry.Format == "raw" {
			fmt.Fprintf(c.Output, "\nFormat: %s\n", entry.Format)
		}
		fmt.Fprintf(c.Output, "Value:\n%s\n", string(entry.Value))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}

func (c *DeleteBucketContentsCmd) Run(ctx context.Context, adminSocket adminapi.SocketPath) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	url := fmt.Sprintf("http://unix/admin/boltdb/buckets/%s", c.BucketName)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := adminapi.NewClient(adminSocket).Do(req)
	if err != nil {
		return fmt.Errorf("call admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("bucket not found")
	}

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Fprintf(c.Output, "Bucket %s emptied successfully.\n", c.BucketName)
	return nil
}
