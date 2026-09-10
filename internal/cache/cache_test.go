package cache

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPutAndGetRoundTrip(t *testing.T) {
	store := New(Options{Dir: t.TempDir(), SchemaKey: "v1"})

	if _, _, _, ok := store.Get("https://api.github.com/thing"); ok {
		t.Fatal("empty cache must not report a hit")
	}

	store.Put("https://api.github.com/thing", `"etag-1"`, []byte(`{"value":1}`), "")

	etag, body, _, ok := store.Get("https://api.github.com/thing")
	if !ok || etag != `"etag-1"` || string(body) != `{"value":1}` {
		t.Fatalf("Get returned %q, %q, %v", etag, body, ok)
	}
}

func TestEntriesSurviveAcrossStores(t *testing.T) {
	dir := t.TempDir()

	first := New(Options{Dir: dir, SchemaKey: "v1"})
	first.Put("https://api.github.com/thing", `"etag-1"`, []byte(`{"value":1}`), "")
	if err := first.Save(); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	second := New(Options{Dir: dir, SchemaKey: "v1"})
	etag, body, _, ok := second.Get("https://api.github.com/thing")
	if !ok || etag != `"etag-1"` || string(body) != `{"value":1}` {
		t.Fatalf("a saved entry must be readable by a later run, got %q, %q, %v", etag, body, ok)
	}
}

// A schema change must invalidate cached bodies, otherwise a new collector
// version could reuse responses it can no longer interpret.
func TestSchemaChangeInvalidatesEntries(t *testing.T) {
	dir := t.TempDir()

	first := New(Options{Dir: dir, SchemaKey: "v1"})
	first.Put("https://api.github.com/thing", `"etag-1"`, []byte(`{"value":1}`), "")
	if err := first.Save(); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	second := New(Options{Dir: dir, SchemaKey: "v2"})
	if _, _, _, ok := second.Get("https://api.github.com/thing"); ok {
		t.Fatal("entries from a different schema version must be ignored")
	}
}

func TestMaxAgeExpiresEntries(t *testing.T) {
	dir := t.TempDir()

	first := New(Options{Dir: dir, SchemaKey: "v1"})
	first.Put("https://api.github.com/thing", `"etag-1"`, []byte(`{"value":1}`), "")
	if err := first.Save(); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	expired := New(Options{Dir: dir, SchemaKey: "v1", MaxAge: time.Nanosecond})
	time.Sleep(2 * time.Millisecond)
	if _, _, _, ok := expired.Get("https://api.github.com/thing"); ok {
		t.Fatal("entries older than the maximum age must be ignored")
	}
}

func TestClearRemovesEntries(t *testing.T) {
	dir := t.TempDir()
	store := New(Options{Dir: dir, SchemaKey: "v1"})
	store.Put("https://api.github.com/thing", `"etag-1"`, []byte(`{"value":1}`), "")
	if err := store.Save(); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	if err := store.Clear(); err != nil {
		t.Fatalf("Clear returned an error: %v", err)
	}
	if _, _, _, ok := store.Get("https://api.github.com/thing"); ok {
		t.Fatal("Clear must discard entries")
	}

	reopened := New(Options{Dir: dir, SchemaKey: "v1"})
	if _, _, _, ok := reopened.Get("https://api.github.com/thing"); ok {
		t.Fatal("Clear must remove entries from disk as well as memory")
	}
}

// A disabled cache must behave like a working one so callers never branch on
// whether caching is available.
func TestDisabledCacheIsSafe(t *testing.T) {
	store := New(Options{})
	if store.Enabled() {
		t.Fatal("a cache without a directory must report itself disabled")
	}

	store.Put("key", "etag", []byte("body"), "")
	if _, _, _, ok := store.Get("key"); ok {
		t.Fatal("a disabled cache must never report a hit")
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save on a disabled cache returned an error: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear on a disabled cache returned an error: %v", err)
	}
	if store.Dir() != "" {
		t.Fatal("a disabled cache has no directory")
	}
}

func TestNilStoreIsSafe(t *testing.T) {
	var store *Store
	store.Put("key", "etag", []byte("body"), "")
	if _, _, _, ok := store.Get("key"); ok {
		t.Fatal("a nil cache must never report a hit")
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save on a nil cache returned an error: %v", err)
	}
	if store.Enabled() {
		t.Fatal("a nil cache is not enabled")
	}
}

func TestEmptyETagIsNotStored(t *testing.T) {
	store := New(Options{Dir: t.TempDir(), SchemaKey: "v1"})
	store.Put("key", "", []byte("body"), "")
	if _, _, _, ok := store.Get("key"); ok {
		t.Fatal("a response without an ETag cannot be revalidated and must not be cached")
	}
}

func TestPathsAreContainedInTheCacheDirectory(t *testing.T) {
	dir := t.TempDir()
	store := New(Options{Dir: dir, SchemaKey: "v1"})

	// Keys are hashed, so a URL containing path traversal cannot escape the
	// cache directory.
	path := store.path("https://api.github.com/../../etc/passwd")
	if filepath.Dir(path) != dir {
		t.Fatalf("cache file %q escaped the cache directory %q", path, dir)
	}
}
