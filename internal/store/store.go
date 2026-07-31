// Package store persists the rule set to disk so a daemon restart doesn't
// silently drop every blocklist entry. It intentionally stays dead simple —
// a JSON file behind a mutex — because the source of truth for "what's
// actually being filtered right now" is always the eBPF map; this is just
// there to repopulate it on boot.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	IP        string `json:"ip"`
	Label     string `json:"label,omitempty"`
	RateLimit uint32 `json:"rate_limit_pps,omitempty"`
	// BandwidthLimit persists Phase 25's QoS byte-rate cap (kbps) so it
	// survives a daemon restart the same way RateLimit already does.
	BandwidthLimit uint32    `json:"rate_limit_kbps,omitempty"`
	Reason         uint8     `json:"reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type Store struct {
	mu   sync.Mutex
	path string
}

// New returns a Store backed by the file at path, creating parent
// directories as needed.
func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

// Load reads the persisted rule set. A missing file is treated as an empty
// store rather than an error, since that's the expected state on first run.
func (s *Store) Load() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// Save overwrites the persisted rule set atomically (write to a temp file,
// then rename) so a crash mid-write can't corrupt the store.
func (s *Store) Save(entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
