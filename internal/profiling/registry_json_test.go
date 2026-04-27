package profiling

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistrySaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")

	reg := &Registry{
		UpdatedAt: time.Now(),
		Resolvers: map[string]*ResolverProfile{
			"1.2.3.4:53": {
				Identity: ResolverIdentity{
					IP:   "1.2.3.4",
					Port: 53,
				},
				Viability: ResolverViability{
					Status: ViabilityViable,
				},
				Upload: Envelope{RecommendedBytes: 64, CeilingBytes: 80},
			},
		},
	}

	if err := SaveRegistryAtomic(path, reg); err != nil {
		t.Fatalf("SaveRegistryAtomic failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected registry file to exist: %v", err)
	}

	loaded, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}
	if loaded == nil || loaded.Resolvers == nil {
		t.Fatalf("expected loaded registry to be non-nil")
	}
	got := loaded.Resolvers["1.2.3.4:53"]
	if got == nil || got.Identity.IP != "1.2.3.4" || got.Identity.Port != 53 {
		t.Fatalf("unexpected loaded profile: %#v", got)
	}
	if got.Viability.Status != ViabilityViable {
		t.Fatalf("unexpected viability: %v", got.Viability.Status)
	}
	if got.Upload.RecommendedBytes != 64 || got.Upload.CeilingBytes != 80 {
		t.Fatalf("unexpected upload envelope: %#v", got.Upload)
	}
}
