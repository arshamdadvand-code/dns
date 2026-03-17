// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfigNormalizesAndLoadsResolvers(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "socks5"
DOMAINS = ["V.Domain.com", "v.domain.com."]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	if err := os.WriteFile(resolversPath, []byte(`
# comment
8.8.8.8
1.1.1.1:5353
`), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.ProtocolType != "SOCKS5" {
		t.Fatalf("unexpected protocol type: got=%q want=%q", cfg.ProtocolType, "SOCKS5")
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0] != "v.domain.com" {
		t.Fatalf("unexpected domains: %+v", cfg.Domains)
	}
	if cfg.ResolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected resolver port for 8.8.8.8: got=%d want=%d", cfg.ResolverMap["8.8.8.8"], 53)
	}
	if cfg.ResolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected resolver port for 1.1.1.1: got=%d want=%d", cfg.ResolverMap["1.1.1.1"], 5353)
	}
}

func TestLoadClientConfigRejectsInvalidProtocol(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "udp"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	if _, err := LoadClientConfig(configPath); err == nil {
		t.Fatal("LoadClientConfig should reject an invalid PROTOCOL_TYPE")
	}
}
