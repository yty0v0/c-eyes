package netscan

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/glebarez/sqlite"
)

type assetStore struct {
	db *sql.DB
	mu sync.Mutex
}

func defaultStorePath() string {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".c-eyes", "netscan-assets.db")
	}
	return "netscan-assets.db"
}

func openAssetStore(path string) (*assetStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("asset store path is empty")
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

	if err := initAssetSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &assetStore{db: db}, nil
}

func (s *assetStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *assetStore) upsert(ctx context.Context, row AssetRow, nowMs int64) (int64, int64, error) {
	if s == nil || s.db == nil {
		return nowMs, nowMs, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var firstSeen int64
	err := s.db.QueryRowContext(ctx, "SELECT first_seen FROM netscan_assets WHERE asset_id = ?", row.AssetID).Scan(&firstSeen)
	switch {
	case err == nil:
		_, err = s.db.ExecContext(ctx, `
UPDATE netscan_assets
SET ip_address = ?, mac_address = ?, hostname = ?, mac_vendor = ?, os_family = ?, device_type = ?, asset_status = ?, last_seen = ?
WHERE asset_id = ?`,
			row.IPAddress, nullableString(row.MACAddress), nullableString(row.Hostname), nullableString(row.MACVendor),
			row.OSFamily, row.DeviceType, row.AssetStatus, nowMs, row.AssetID,
		)
		if err != nil {
			return 0, 0, err
		}
		return firstSeen, nowMs, nil
	case errors.Is(err, sql.ErrNoRows):
		firstSeen = nowMs
		_, err = s.db.ExecContext(ctx, `
INSERT INTO netscan_assets (asset_id, ip_address, mac_address, hostname, mac_vendor, os_family, device_type, asset_status, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.AssetID, row.IPAddress, nullableString(row.MACAddress), nullableString(row.Hostname), nullableString(row.MACVendor),
			row.OSFamily, row.DeviceType, row.AssetStatus, firstSeen, nowMs,
		)
		if err != nil {
			return 0, 0, err
		}
		return firstSeen, nowMs, nil
	default:
		return 0, 0, err
	}
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func initAssetSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS netscan_assets (
  asset_id TEXT PRIMARY KEY,
  ip_address TEXT NOT NULL,
  mac_address TEXT,
  hostname TEXT,
  mac_vendor TEXT,
  os_family TEXT NOT NULL,
  device_type TEXT NOT NULL,
  asset_status TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);`)
	if err != nil {
		return err
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_netscan_assets_ip ON netscan_assets(ip_address);`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_netscan_assets_last_seen ON netscan_assets(last_seen);`)
	return nil
}
