// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"masterdnsvpn-go/internal/config"
)

type valueSource string

const (
	sourceBootstrapManual     valueSource = "bootstrap_manual"
	sourceDerivedFromProfiling valueSource = "derived_from_profiling"
	sourceDerivedFromSystem   valueSource = "derived_from_system"
	sourceFixedDefault        valueSource = "fixed_protocol_default"
	sourceNotDerivedYet       valueSource = "not_derived_yet"
)

type configFieldSummary struct {
	Name   string      `json:"name"`
	Value  any         `json:"value"`
	Source valueSource `json:"source"`
}

type autoProfilePersistedSummary struct {
	GeneratedAt time.Time `json:"generated_at"`
	Domain      string    `json:"domain"`
	RunElapsedSeconds float64 `json:"run_elapsed_seconds"`

	ResolverFile config.ResolverFileStats `json:"resolver_file"`

	Stages struct {
		TotalInputUnique    int `json:"total_input_unique"`
		Stage0Attempted     int `json:"stage0_attempted"`
		Stage0Viable        int `json:"stage0_viable"`
		Stage0Timeout       int `json:"stage0_timeout"`
		Stage0Malformed     int `json:"stage0_malformed"`
		Stage1UploadFail    int `json:"stage1_upload_fail"`
		Stage1DownloadFail  int `json:"stage1_download_fail"`
		Stage2Refined       int `json:"stage2_refined"`
		ProfileComplete     int `json:"final_profile_complete"`
		Active              int `json:"active"`
		Reserve             int `json:"reserve"`
	} `json:"stages"`

	RejectReasons struct {
		Stage0MalformedSubreasons map[string]int `json:"stage0_malformed_subreasons"`
		Stage1FailReasons         map[string]int `json:"stage1_fail_reasons"`
	} `json:"reject_reasons"`

	Derived derivedRuntimeConfig `json:"derived_runtime"`

	// Full config table: every TOML key + source.
	ClientConfigFields []configFieldSummary `json:"client_config_fields"`

	// Extra runtime-only derived knobs (not TOML fields yet).
	RuntimeDerived []configFieldSummary `json:"runtime_derived"`
}

func persistAutoProfileSummary(cfg config.ClientConfig, snap autoProfileSnapshot, derived derivedRuntimeConfig, outPath string) (string, error) {
	sum := autoProfilePersistedSummary{
		GeneratedAt: time.Now(),
		Domain:      snap.Domain,
		RunElapsedSeconds: snap.Elapsed.Seconds(),
		ResolverFile: cfg.ResolverFileStats,
		Derived: derived,
	}
	sum.Stages.TotalInputUnique = snap.UniqueInput
	sum.Stages.Stage0Attempted = snap.Stage0Attempted
	sum.Stages.Stage0Viable = snap.Stage0Viable
	sum.Stages.Stage0Timeout = snap.Stage0Timeout
	sum.Stages.Stage0Malformed = snap.Stage0Malformed
	sum.Stages.Stage1UploadFail = snap.Stage1UploadFail
	sum.Stages.Stage1DownloadFail = snap.Stage1DownloadFail
	sum.Stages.Stage2Refined = snap.Stage2Refined
	sum.Stages.ProfileComplete = snap.ProfileComplete
	if snap.DerivedAvailable {
		sum.Stages.Active = snap.DerivedActive
		sum.Stages.Reserve = snap.DerivedReserve
	}

	sum.RejectReasons.Stage0MalformedSubreasons = map[string]int{}
	for _, kv := range snap.MalformedSubTop {
		sum.RejectReasons.Stage0MalformedSubreasons[kv.k] = kv.v
	}
	// Persist full maps when available by re-snapshotting from stats is not exposed here;
	// we keep top reasons in Phase 1 for minimal storage.
	sum.RejectReasons.Stage1FailReasons = map[string]int{}
	for _, kv := range snap.StageFailTop {
		sum.RejectReasons.Stage1FailReasons[kv.k] = kv.v
	}

	sum.ClientConfigFields = summarizeClientConfigFields(cfg, derived)

	sum.RuntimeDerived = []configFieldSummary{
		{Name: "synced_upload_mtu", Value: snap.DerivedUpload, Source: sourceDerivedFromProfiling},
		{Name: "synced_download_mtu", Value: snap.DerivedDownload, Source: sourceDerivedFromProfiling},
		{Name: "active_resolvers", Value: snap.DerivedActiveList, Source: sourceDerivedFromProfiling},
		{Name: "reserve_resolvers", Value: snap.DerivedReserveList, Source: sourceDerivedFromProfiling},
		{Name: "confidence", Value: snap.DerivedConfidence, Source: sourceDerivedFromProfiling},
		{Name: "fragile", Value: snap.DerivedFragile, Source: sourceDerivedFromProfiling},
	}

	raw, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return "", err
	}
	if outPath == "" {
		outPath = filepath.Join(cfg.ConfigDir, "autoprofile_summary_"+time.Now().Format("20060102_150405")+".json")
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return "", err
	}
	return outPath, nil
}

func summarizeClientConfigFields(cfg config.ClientConfig, derived derivedRuntimeConfig) []configFieldSummary {
	// Fields overridden by derived runtime (Phase 1 authority).
	derivedKeys := map[string]struct{}{
		"PACKET_DUPLICATION_COUNT": {},
		"SETUP_PACKET_DUPLICATION_COUNT": {},
		"STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD": {},
		"STREAM_RESOLVER_FAILOVER_COOLDOWN": {},
	}

	out := make([]configFieldSummary, 0, 128)
	rv := reflect.ValueOf(cfg)
	rt := reflect.TypeOf(cfg)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tomlKey := f.Tag.Get("toml")
		if tomlKey == "" || tomlKey == "-" {
			continue
		}
		v := rv.Field(i).Interface()

		src := sourceFixedDefault
		if cfg.DefinedTOMLKeys != nil && cfg.DefinedTOMLKeys[tomlKey] {
			src = sourceBootstrapManual
		}
		if _, ok := derivedKeys[tomlKey]; ok {
			src = sourceDerivedFromProfiling
			// Show final value as what derived applies (not the pre-override TOML value).
			switch tomlKey {
			case "PACKET_DUPLICATION_COUNT":
				v = derived.PacketDuplicationCount
			case "SETUP_PACKET_DUPLICATION_COUNT":
				v = derived.SetupDuplicationCount
			case "STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD":
				v = derived.FailoverResendThreshold
			case "STREAM_RESOLVER_FAILOVER_COOLDOWN":
				v = derived.FailoverCooldownSeconds
			}
		}

		out = append(out, configFieldSummary{Name: tomlKey, Value: v, Source: src})
	}

	// Deterministic output ordering.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s valueSource) String() string { return string(s) }

func mustNotBeEmpty(label, v string) error {
	if v == "" {
		return fmt.Errorf("%s is empty", label)
	}
	return nil
}

