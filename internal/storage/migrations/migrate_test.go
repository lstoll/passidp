package migrations

import (
	"reflect"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	got := splitStatements(`
-- comment
CREATE TABLE foo (
    id TEXT
);

CREATE INDEX idx_foo ON foo (id);
`)
	want := []string{
		"CREATE TABLE foo (\nid TEXT\n)",
		"CREATE INDEX idx_foo ON foo (id)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitStatements() = %#v, want %#v", got, want)
	}
}
