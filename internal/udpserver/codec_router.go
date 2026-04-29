package udpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"masterdnsvpn-go/internal/security"
)

// domainKeyringEntry provides per-domain codec configuration.
// This enables multiple logical instances (domain+key+method) to share one server process.
type domainKeyringEntry struct {
	Domain           string `json:"domain"`
	EncryptionMethod int    `json:"encryption_method"`
	Key              string `json:"key"`
	KeyFile          string `json:"key_file"`
}

func loadDomainKeyring(configDir string, path string) ([]domainKeyringEntry, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, "", nil
	}
	if !filepath.IsAbs(path) && configDir != "" {
		path = filepath.Join(configDir, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, abs, err
	}
	var out []domainKeyringEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, abs, err
	}
	for i := range out {
		out[i].Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(out[i].Domain)), ".")
		out[i].Key = strings.TrimSpace(out[i].Key)
		out[i].KeyFile = strings.TrimSpace(out[i].KeyFile)
		if out[i].EncryptionMethod < 0 || out[i].EncryptionMethod > 5 {
			out[i].EncryptionMethod = 1
		}
	}
	return out, abs, nil
}

func buildCodecByDomain(configDir string, keyringPath string) (map[string]*security.Codec, error) {
	entries, abs, err := loadDomainKeyring(configDir, keyringPath)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]*security.Codec, len(entries))
	var firstErr error
	errCount := 0
	for _, e := range entries {
		if e.Domain == "" {
			continue
		}
		rawKey := e.Key
		if rawKey == "" && e.KeyFile != "" {
			p := e.KeyFile
			if !filepath.IsAbs(p) && configDir != "" {
				p = filepath.Join(configDir, p)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("read key_file failed for domain=%s path=%s: %w", e.Domain, p, err)
				}
				errCount++
				continue
			}
			rawKey = strings.TrimSpace(string(b))
		}
		if rawKey == "" {
			continue
		}
		codec, err := security.NewCodec(e.EncryptionMethod, rawKey)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("codec init failed for domain=%s: %w", e.Domain, err)
			}
			errCount++
			continue
		}
		out[e.Domain] = codec
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, nil
	}
	if errCount > 0 {
		return out, fmt.Errorf("domain keyring partially loaded: errors=%d first=%v keyring=%s", errCount, firstErr, abs)
	}
	return out, nil
}
