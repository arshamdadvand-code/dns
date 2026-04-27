package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const storeVersion = 2

func loadStore(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return &Store{
				Version:              storeVersion,
				BaseCandidates:       make(map[string]BaseCandidate),
				Overlays:             make(map[string]map[string]InstanceOverlay),
				Instances:            make(map[string]InstanceState),
				FeedCursorByInstance: make(map[string]int),
			}, nil
		}
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("store parse failed: %w", err)
	}
	if s.Version == 0 {
		s.Version = storeVersion
	}
	if s.BaseCandidates == nil {
		s.BaseCandidates = make(map[string]BaseCandidate)
	}
	if s.Overlays == nil {
		s.Overlays = make(map[string]map[string]InstanceOverlay)
	}
	if s.Instances == nil {
		s.Instances = make(map[string]InstanceState)
	}
	if s.FeedCursorByInstance == nil {
		s.FeedCursorByInstance = make(map[string]int)
	}
	return &s, nil
}

func saveStore(path string, s *Store) error {
	if s == nil {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	s.Version = storeVersion
	s.LastSavedAt = time.Now()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, abs)
}
