package filescan

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "github.com/glebarez/sqlite"
)

type SQLiteCacheStore struct {
	db *sql.DB
}

func NewSQLiteCacheStore(path string) (*SQLiteCacheStore, error) {
	if path == "" {
		return nil, errors.New("cache path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := initCacheSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteCacheStore{db: db}, nil
}

func (s *SQLiteCacheStore) Get(ctx context.Context, path string, modTime time.Time) (*CacheEntry, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT file_hash, last_modified, scan_result, last_scan_time FROM scan_cache WHERE file_path = ?`, path)
	var hash string
	var lastModified int64
	var scanResult string
	var lastScan int64
	if err := row.Scan(&hash, &lastModified, &scanResult, &lastScan); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if lastModified != modTime.Unix() {
		return nil, false, nil
	}
	entry := &CacheEntry{
		Path:         path,
		Hash:         hash,
		LastModified: time.Unix(lastModified, 0).UTC(),
		ScanResult:   ScanResult(scanResult),
		LastScanTime: time.Unix(lastScan, 0).UTC(),
	}
	return entry, true, nil
}

func (s *SQLiteCacheStore) Put(ctx context.Context, entry CacheEntry) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO scan_cache (file_path, file_hash, last_modified, scan_result, last_scan_time)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(file_path) DO UPDATE SET
 file_hash=excluded.file_hash,
 last_modified=excluded.last_modified,
 scan_result=excluded.scan_result,
 last_scan_time=excluded.last_scan_time
`, entry.Path, entry.Hash, entry.LastModified.Unix(), string(entry.ScanResult), entry.LastScanTime.Unix())
	return err
}

func (s *SQLiteCacheStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func initCacheSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS scan_cache (
  file_path TEXT PRIMARY KEY,
  file_hash TEXT,
  last_modified INTEGER,
  scan_result TEXT,
  last_scan_time INTEGER
);
`)
	if err != nil {
		return err
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_cache_mtime ON scan_cache(last_modified);`)
	return nil
}

func DefaultCachePath() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Join(filepath.Dir(exe), "scan-cache.db")
	}
	return "scan-cache.db"
}
