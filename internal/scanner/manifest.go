package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func loadManifest(path string) ([]InstanceManifest, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []InstanceManifest
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range out {
		out[i].InstanceID = strings.TrimSpace(out[i].InstanceID)
		out[i].Domain = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(out[i].Domain), "."))
		out[i].KeyFingerprint = strings.TrimSpace(strings.ToLower(out[i].KeyFingerprint))
		if out[i].EncryptionMethod < 0 || out[i].EncryptionMethod > 5 {
			out[i].EncryptionMethod = 1
		}
		if out[i].Enabled == false && out[i].Intent == "" {
			// leave disabled
		}
		_ = now
	}
	return out, nil
}
