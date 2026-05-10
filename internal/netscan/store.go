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
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		return filepath.Join(filepath.Dir(exe), "netscan-assets.db")
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

	if upgradedFirstSeen, upgraded, err := s.upgradeWeakIdentity(ctx, row, nowMs); err != nil {
		return 0, 0, err
	} else if upgraded {
		return upgradedFirstSeen, nowMs, nil
	}

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

func (s *assetStore) upgradeWeakIdentity(ctx context.Context, row AssetRow, nowMs int64) (int64, bool, error) {
	if s == nil || s.db == nil || row.MACAddress == nil {
		return 0, false, nil
	}
	mac := strings.TrimSpace(*row.MACAddress)
	ip := strings.TrimSpace(row.IPAddress)
	if mac == "" || ip == "" {
		return 0, false, nil
	}

	strongID := row.AssetID
	weakID := deterministicAssetID(ip, "")
	if weakID == strongID {
		return 0, false, nil
	}

	var existingStrong string
	err := s.db.QueryRowContext(ctx, "SELECT asset_id FROM netscan_assets WHERE asset_id = ?", strongID).Scan(&existingStrong)
	switch {
	case err == nil:
		return 0, false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return 0, false, err
	}

	var weak assetStoreRow
	err = s.db.QueryRowContext(ctx, `
SELECT asset_id, ip_address, mac_address, hostname, mac_vendor, os_family, device_type, asset_status, first_seen, last_seen
FROM netscan_assets WHERE asset_id = ?`, weakID).Scan(
		&weak.AssetID,
		&weak.IPAddress,
		&weak.MACAddress,
		&weak.Hostname,
		&weak.MACVendor,
		&weak.OSFamily,
		&weak.DeviceType,
		&weak.AssetStatus,
		&weak.FirstSeen,
		&weak.LastSeen,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, err
	}

	if !weakIdentityUpgradeAllowed(weak, row) {
		return 0, false, nil
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM netscan_assets WHERE asset_id = ?`, weakID); err != nil {
		return 0, false, err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO netscan_assets (asset_id, ip_address, mac_address, hostname, mac_vendor, os_family, device_type, asset_status, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strongID,
		row.IPAddress,
		nullableString(row.MACAddress),
		nullableString(row.Hostname),
		nullableString(row.MACVendor),
		row.OSFamily,
		row.DeviceType,
		row.AssetStatus,
		weak.FirstSeen,
		nowMs,
	); err != nil {
		return 0, false, err
	}
	return weak.FirstSeen, true, nil
}

type assetStoreRow struct {
	AssetID     string
	IPAddress   string
	MACAddress  sql.NullString
	Hostname    sql.NullString
	MACVendor   sql.NullString
	OSFamily    string
	DeviceType  string
	AssetStatus string
	FirstSeen   int64
	LastSeen    int64
}

func weakIdentityUpgradeAllowed(existing assetStoreRow, current AssetRow) bool {
	if strings.TrimSpace(existing.IPAddress) == "" || strings.TrimSpace(current.IPAddress) == "" {
		return false
	}
	if strings.TrimSpace(existing.IPAddress) != strings.TrimSpace(current.IPAddress) {
		return false
	}

	if !sameOptionalString(existing.Hostname, current.Hostname) {
		return false
	}
	if !sameNormalizedText(existing.OSFamily, current.OSFamily) {
		return false
	}
	if !sameNormalizedText(existing.DeviceType, current.DeviceType) {
		return false
	}
	return true
}

func sameOptionalString(existing sql.NullString, current *string) bool {
	existingVal := ""
	if existing.Valid {
		existingVal = existing.String
	}
	currentVal := ""
	if current != nil {
		currentVal = *current
	}
	existingVal = strings.TrimSpace(strings.ToLower(existingVal))
	currentVal = strings.TrimSpace(strings.ToLower(currentVal))
	if existingVal == "" || currentVal == "" {
		return true
	}
	return existingVal == currentVal
}

func sameNormalizedText(existing, current string) bool {
	existing = strings.TrimSpace(strings.ToLower(existing))
	current = strings.TrimSpace(strings.ToLower(current))
	if existing == "" || current == "" {
		return true
	}
	return existing == current
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
