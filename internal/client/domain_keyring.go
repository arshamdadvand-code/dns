package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"masterdnsvpn-go/internal/security"
)

type domainKeyringEntry struct {
	Domain           string `json:"domain"`
	EncryptionMethod int    `json:"encryption_method"`
	Key              string `json:"key"`
	KeyFile          string `json:"key_file"`
}

// DomainKeyringEntryPublic is an exported view used by cmd/client multi-instance
// boot logic without exposing internal parsing details.
type DomainKeyringEntryPublic struct {
	Domain           string
	EncryptionMethod int
	Key              string
}

// LoadDomainKeyringForMulti is a narrow exported helper used by the multi-instance
// host in cmd/client to build per-domain client configs.
func LoadDomainKeyringForMulti(configDir string, path string) ([]DomainKeyringEntryPublic, string, error) {
	entries, abs, err := loadDomainKeyring(configDir, path)
	if err != nil {
		return nil, abs, err
	}
	out := make([]DomainKeyringEntryPublic, 0, len(entries))
	for _, e := range entries {
		if e.Domain == "" || e.Key == "" {
			continue
		}
		out = append(out, DomainKeyringEntryPublic{
			Domain:           e.Domain,
			EncryptionMethod: e.EncryptionMethod,
			Key:              e.Key,
		})
	}
	return out, abs, nil
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

func buildCodecByDomain(configDir string, keyringPath string) (map[string]*security.Codec, string, error) {
	entries, abs, err := loadDomainKeyring(configDir, keyringPath)
	if err != nil {
		return nil, abs, err
	}
	if len(entries) == 0 {
		return nil, abs, nil
	}
	out := make(map[string]*security.Codec, len(entries))
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
				return nil, abs, err
			}
			rawKey = strings.TrimSpace(string(b))
		}
		if rawKey == "" {
			continue
		}
		codec, err := security.NewCodec(e.EncryptionMethod, rawKey)
		if err != nil {
			return nil, abs, err
		}
		out[e.Domain] = codec
	}
	if len(out) == 0 {
		return nil, abs, nil
	}
	return out, abs, nil
}

func (c *Client) codecForDomain(domain string) *security.Codec {
	if c == nil {
		return nil
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain != "" && c.codecByDomain != nil {
		if cd := c.codecByDomain[domain]; cd != nil {
			return cd
		}
	}
	return c.codec
}
