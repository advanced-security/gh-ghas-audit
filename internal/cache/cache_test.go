package cache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestSchemaChangesReplaceTheSameCacheEntry(t *testing.T) {
	dir := t.TempDir()
	for _, schema := range []string{"v1", "v2", "v3"} {
		store := New(Options{Dir: dir, SchemaKey: schema})
		if _, _, _, ok := store.Get("same-url"); ok {
			t.Fatal("an incompatible schema was reused")
		}
		store.Put("same-url", "etag", []byte(schema), "")
		if err := store.Save(); err != nil {
			t.Fatal(err)
		}
		if _, body, _, ok := store.Get("same-url"); !ok || string(body) != schema {
			t.Fatalf("new schema was not stored: %q", body)
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 1 {
			t.Fatalf("schema changes created additional generations: files=%d, err=%v", len(files), err)
		}
	}
}

func TestCleanupPreservesUnrelatedFiles(t *testing.T) {
	for _, operation := range []string{"clear", "prune"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			store := New(Options{Dir: dir, SchemaKey: "v1", MaxAge: time.Hour})
			old := time.Now().Add(-2 * time.Hour)
			preserved := []string{
				"package.json",
				"report.json",
				strings.Repeat("a", 63) + ".json",
				strings.Repeat("a", 65) + ".json",
				strings.Repeat("a", 63) + "g.json",
				strings.Repeat("B", 64) + ".json",
				strings.Repeat("c", 64) + ".JSON",
				strings.Repeat("a", 64) + ".json.bak",
				"entry-unfinished.tmp",
			}
			for _, name := range preserved {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(`{"keep":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
			}

			for _, name := range []string{"data.json", strings.Repeat("a", 64) + ".json"} {
				path := filepath.Join(dir, name)
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
				preserved = append(preserved, name)
			}

			store.Put("stale", `"etag"`, []byte(`{"stale":true}`), "")
			store.Put("fresh", `"etag"`, []byte(`{"fresh":true}`), "")
			if err := store.Save(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(store.path("stale"), old, old); err != nil {
				t.Fatal(err)
			}

			var err error
			if operation == "clear" {
				err = store.Clear()
			} else {
				err = store.Prune()
			}
			if err != nil {
				t.Fatalf("%s returned an error: %v", operation, err)
			}
			for _, name := range preserved {
				if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
					t.Errorf("%s must preserve %q: %v", operation, name, err)
				}
			}
			if _, err := os.Stat(store.path("stale")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s must remove stale cache entries, got %v", operation, err)
			}
			_, err = os.Stat(store.path("fresh"))
			if operation == "prune" && err != nil {
				t.Errorf("Prune must preserve fresh cache entries: %v", err)
			}
			if operation == "clear" && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Clear must remove fresh cache entries, got %v", err)
			}
		})
	}
}

func TestCleanupPreservesSymlinks(t *testing.T) {
	for _, operation := range []string{"clear", "prune"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			store := New(Options{Dir: dir, MaxAge: time.Nanosecond})
			target := filepath.Join(dir, "keep.txt")
			if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := store.path("symlink")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			time.Sleep(2 * time.Millisecond)

			var err error
			if operation == "clear" {
				err = store.Clear()
			} else {
				err = store.Prune()
			}
			if err != nil {
				t.Fatalf("%s returned an error: %v", operation, err)
			}
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Errorf("%s must preserve cache-named symlinks, got %v, %v", operation, info, err)
			}
			if content, err := os.ReadFile(target); err != nil || string(content) != "keep" {
				t.Errorf("%s must preserve symlink targets, got %q, %v", operation, content, err)
			}
		})
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
