// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package profiling

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type Registry struct {
	UpdatedAt time.Time                   `json:"updated_at"`
	Resolvers map[string]*ResolverProfile `json:"resolvers"`
}

func LoadRegistry(path string) (*Registry, error) {
	if path == "" {
		return &Registry{UpdatedAt: time.Now(), Resolvers: map[string]*ResolverProfile{}}, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Registry{UpdatedAt: time.Now(), Resolvers: map[string]*ResolverProfile{}}, nil
		}
		return nil, err
	}

	var reg Registry
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, err
	}
	if reg.Resolvers == nil {
		reg.Resolvers = map[string]*ResolverProfile{}
	}
	return &reg, nil
}

func SaveRegistryAtomic(path string, reg *Registry) error {
	if path == "" || reg == nil {
		return nil
	}

	reg.UpdatedAt = time.Now()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	raw, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
