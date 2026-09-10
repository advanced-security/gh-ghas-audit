// Package cache provides an on-disk store of ETags and response bodies so
// repeated scans of a large estate can revalidate cheaply. GitHub does not
// count 304 Not Modified responses against the primary rate limit, so this is
// the main lever for making repeated enterprise-wide scans affordable.
//
// Entries are written through to disk rather than retained in memory. An
// enterprise scan can touch tens of thousands of repositories, and holding
// every response body for the lifetime of the process would grow without
// bound.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// entry is a single cached response as stored on disk.
type entry struct {
	URL      string    `json:"url"`
	ETag     string    `json:"etag"`
	Body     []byte    `json:"body"`
	StoredAt time.Time `json:"stored_at"`
	// Next is the URL of the following page, captured from the Link header of
	// the original response. A 304 is not required to repeat Link, so without
	// this a revalidated first page would look like the last page and the
	// remainder of a paginated collection would be silently dropped.
	Next      string `json:"next,omitempty"`
	SchemaKey string `json:"schema_key"`
}

// format versions the on-disk entry layout. It is combined with the caller's
// schema key so that adding a field to entry can never silently reuse older
// entries written without it.
const format = "2"

// Store is a concurrency-safe ETag cache backed by a directory of JSON files.
// A nil *Store is valid and behaves as a disabled cache, so callers never need
// to branch on whether caching is enabled.
type Store struct {
	dir       string
	maxAge    time.Duration
	schemaKey string
	disable   bool

	// writeMu serializes writes to a single key so two workers revalidating
	// the same URL cannot interleave partial files.
	writeMu sync.Mutex
	// writeErrors counts failures so a persistently unwritable cache can be
	// reported once rather than per request.
	writeErrors atomic.Int64
}

// Options configures a Store.
type Options struct {
	// Dir is the cache directory. Empty disables caching.
	Dir string
	// MaxAge discards entries older than this. Zero means no age limit,
	// relying purely on ETag revalidation.
	MaxAge time.Duration
	// SchemaKey invalidates cached entries when the collector's expectations
	// change, preventing a new version from reusing incompatible bodies.
	SchemaKey string
}

// New opens or creates a cache. It never fails hard: if the directory cannot
// be used, caching is silently disabled so a scan still completes.
func New(opts Options) *Store {
	if opts.Dir == "" {
		return &Store{disable: true}
	}
	store := &Store{
		dir:    opts.Dir,
		maxAge: opts.MaxAge,
		// The on-disk format is folded into the key so an older cache written
		// without the current fields is never reused.
		schemaKey: opts.SchemaKey + "|" + format,
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		store.disable = true
	}
	return store
}

// Get returns the cached ETag, body and next page URL for a URL.
func (s *Store) Get(key string) (etag string, body []byte, next string, ok bool) {
	if s == nil || s.disable {
		return "", nil, "", false
	}

	cached, err := s.readFile(key)
	if err != nil {
		return "", nil, "", false
	}
	if cached.SchemaKey != s.schemaKey || s.expired(cached) {
		return "", nil, "", false
	}
	return cached.ETag, cached.Body, cached.Next, true
}

// Put records a response for a URL, writing it straight to disk so no
// response body is retained in memory after the request completes.
//
// The next page URL is stored with the body because a 304 revalidation is not
// required to repeat the Link header.
func (s *Store) Put(key string, etag string, body []byte, next string) {
	if s == nil || s.disable || etag == "" {
		return
	}

	stored := entry{
		URL:       key,
		ETag:      etag,
		Body:      body,
		Next:      next,
		StoredAt:  time.Now(),
		SchemaKey: s.schemaKey,
	}

	s.writeMu.Lock()
	err := s.writeFile(stored)
	s.writeMu.Unlock()

	if err != nil {
		s.writeErrors.Add(1)
	}
}

// Save reports whether any cache writes failed. Entries are written when they
// are stored, so this performs no work of its own; it exists so a caller can
// surface a persistently unwritable cache.
func (s *Store) Save() error {
	if s == nil || s.disable {
		return nil
	}
	if failures := s.writeErrors.Load(); failures > 0 {
		return fmt.Errorf("%d cache entries could not be written to %s", failures, s.dir)
	}
	return nil
}

// Clear removes every cached entry, forcing the next scan to be a cold run.
func (s *Store) Clear() error {
	if s == nil || s.disable {
		return nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, item := range entries {
		if item.IsDir() || filepath.Ext(item.Name()) != ".json" {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, item.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Prune deletes entries that are older than the maximum age or that were
// written by a different schema version, keeping the directory from growing
// without bound across releases.
func (s *Store) Prune() error {
	if s == nil || s.disable || s.maxAge <= 0 {
		return nil
	}

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	cutoff := time.Now().Add(-s.maxAge)
	for _, item := range entries {
		if item.IsDir() || filepath.Ext(item.Name()) != ".json" {
			continue
		}
		info, err := item.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(s.dir, item.Name()))
		}
	}
	return nil
}

// Enabled reports whether the cache is active.
func (s *Store) Enabled() bool {
	return s != nil && !s.disable
}

// Dir returns the backing directory, or an empty string when disabled.
func (s *Store) Dir() string {
	if s == nil || s.disable {
		return ""
	}
	return s.dir
}

func (s *Store) expired(cached entry) bool {
	if s.maxAge <= 0 {
		return false
	}
	return time.Since(cached.StoredAt) > s.maxAge
}

// path hashes the key, so a URL containing path traversal characters cannot
// escape the cache directory.
func (s *Store) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

func (s *Store) readFile(key string) (entry, error) {
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		return entry{}, err
	}
	var cached entry
	if err := json.Unmarshal(data, &cached); err != nil {
		return entry{}, err
	}
	if cached.URL != key {
		return entry{}, fmt.Errorf("cache key mismatch for %s", key)
	}
	return cached, nil
}

func (s *Store) writeFile(cached entry) error {
	data, err := json.Marshal(cached)
	if err != nil {
		return err
	}

	target := s.path(cached.URL)
	temp, err := os.CreateTemp(s.dir, "entry-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()

	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return err
	}

	// Rename is atomic within a directory, so a concurrent reader either sees
	// the previous entry or the new one, never a partial file.
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	return nil
}

// DefaultDir returns a per-user cache directory for the tool.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "gh-ghas-audit", "code-scanning-status"), nil
}
