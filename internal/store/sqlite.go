package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/model"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  profile TEXT NOT NULL,
  targets_json TEXT NOT NULL,
  report_json BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  tenant TEXT NOT NULL DEFAULT '',
  confidence TEXT NOT NULL,
  PRIMARY KEY (scan_id, target, provider_id, tenant)
);
CREATE INDEX IF NOT EXISTS idx_findings_lookup ON findings(target, provider_id);
CREATE TABLE IF NOT EXISTS cache (
  cache_key TEXT PRIMARY KEY,
  detector_version TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  value BLOB NOT NULL
);`)
	return err
}

func (s *Store) Save(ctx context.Context, report model.ScanReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	targetJSON, _ := json.Marshal(report.Metadata.TargetNames)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO scans(id, started_at, profile, targets_json, report_json) VALUES(?,?,?,?,?)`,
		report.Metadata.ScanID, report.Metadata.StartedAt.Format(time.RFC3339Nano), report.Metadata.Profile, string(targetJSON), payload); err != nil {
		return fmt.Errorf("store scan: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings(scan_id,target,provider_id,tenant,confidence) VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, finding := range report.Findings {
		if _, err := stmt.ExecContext(ctx, report.Metadata.ScanID, finding.Target, finding.ProviderID, finding.Tenant, finding.Confidence); err != nil {
			return fmt.Errorf("store finding: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) Load(ctx context.Context, id string) (model.ScanReport, error) {
	var payload []byte
	if err := s.db.QueryRowContext(ctx, `SELECT report_json FROM scans WHERE id=?`, id).Scan(&payload); err != nil {
		return model.ScanReport{}, err
	}
	var report model.ScanReport
	if err := json.Unmarshal(payload, &report); err != nil {
		return model.ScanReport{}, err
	}
	return report, nil
}

func (s *Store) Recent(ctx context.Context, limit int) ([]model.StoredScan, error) {
	if limit < 1 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, started_at, profile, targets_json FROM scans ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scans []model.StoredScan
	for rows.Next() {
		var item model.StoredScan
		var started, targets string
		if err := rows.Scan(&item.ID, &started, &item.Profile, &targets); err != nil {
			return nil, err
		}
		item.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		_ = json.Unmarshal([]byte(targets), &item.TargetList)
		scans = append(scans, item)
	}
	return scans, rows.Err()
}

func (s *Store) PutCache(ctx context.Context, key, detectorVersion string, expiresAt time.Time, value []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cache(cache_key,detector_version,expires_at,value) VALUES(?,?,?,?)
ON CONFLICT(cache_key) DO UPDATE SET detector_version=excluded.detector_version, expires_at=excluded.expires_at, value=excluded.value`,
		key, detectorVersion, expiresAt.Format(time.RFC3339Nano), value)
	return err
}

func (s *Store) GetCache(ctx context.Context, key, detectorVersion string) ([]byte, bool, error) {
	var value []byte
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT expires_at,value FROM cache WHERE cache_key=? AND detector_version=?`, key, detectorVersion).Scan(&expires, &value)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || time.Now().After(expiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM cache WHERE cache_key=?`, key)
		return nil, false, nil
	}
	return value, true, nil
}
