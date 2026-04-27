package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func loadKeyring(path string) (map[string]string, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, abs, nil
		}
		return nil, "", err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, "", err
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		id := strings.TrimSpace(k)
		raw := strings.TrimSpace(v)
		if id == "" || raw == "" {
			continue
		}
		out[id] = raw
	}
	return out, abs, nil
}
