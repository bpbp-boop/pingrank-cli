package accesspath

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSaveCacheReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access-path.json")
	first := Result{Classification: Indeterminate, TestedAt: time.Now().UTC()}
	second := Result{Classification: NAT64, TestedAt: first.TestedAt.Add(time.Second)}
	if err := SaveCache(path, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveCache(path, second); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadCache(path, time.Hour)
	if !ok || got.Classification != NAT64 {
		t.Fatalf("cache = %+v, %t", got, ok)
	}
}
