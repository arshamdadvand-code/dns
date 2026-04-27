package scanner

import "time"

type InstanceManifest struct {
	InstanceID       string `json:"instance_id"`
	Domain           string `json:"domain"`
	KeyFingerprint   string `json:"key_fingerprint"`
	EncryptionMethod int    `json:"encryption_method"`
	Enabled          bool   `json:"enabled"`
	Intent           string `json:"intent,omitempty"`
}

type InstanceLease struct {
	InstanceID string    `json:"instance_id"`
	ClientID   string    `json:"client_id"`
	ExpiresAt  time.Time `json:"expires_at"`

	Demand map[string]bool `json:"demand,omitempty"`
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (e Endpoint) Key() string {
	return e.IP + ":" + itoaPort(e.Port)
}

type BaseCandidate struct {
	Endpoint    Endpoint  `json:"endpoint"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	Source      string    `json:"source"`
}

type OverlayBucket string

const (
	BucketActiveReady    OverlayBucket = "active_ready"
	BucketReserveReady   OverlayBucket = "reserve_ready"
	BucketColdKnown      OverlayBucket = "cold_known"
	BucketQuarantined    OverlayBucket = "quarantined"
	BucketCarrierBlocked OverlayBucket = "carrier_blocked_or_incompatible"
	BucketRetired        OverlayBucket = "retired"
)

type InstanceOverlay struct {
	InstanceID string        `json:"instance_id"`
	Endpoint   Endpoint      `json:"endpoint"`
	Bucket     OverlayBucket `json:"bucket"`

	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	LastValidatedAt  time.Time `json:"last_validated_at"`
	LastResult       string    `json:"last_result"`
	LastSubReason    string    `json:"last_subreason,omitempty"`
	LastRTTms        float64   `json:"last_rtt_ms,omitempty"`
	OKCount          int       `json:"ok_count"`
	FailCount        int       `json:"fail_count"`
	ProfileComplete  bool      `json:"profile_complete,omitempty"`
	UploadRecBytes   int       `json:"upload_recommended_bytes,omitempty"`
	UploadMaxBytes   int       `json:"upload_working_max_bytes,omitempty"`
	DownloadRecBytes int       `json:"download_recommended_bytes,omitempty"`
	DownloadMaxBytes int       `json:"download_working_max_bytes,omitempty"`

	QuarantineUntil time.Time `json:"quarantine_until,omitempty"`
}

type Store struct {
	Version int `json:"version"`

	BaseCandidates map[string]BaseCandidate              `json:"base_candidates"`
	Overlays       map[string]map[string]InstanceOverlay `json:"overlays"`
	Instances      map[string]InstanceState              `json:"instances"`
	FeedStats      FeedStats                             `json:"feed_stats"`
	// FeedCursorByInstance persists feed traversal progress so expand/world scan
	// does not get trapped probing only the beginning of the feed slice.
	FeedCursorByInstance map[string]int `json:"feed_cursor_by_instance,omitempty"`
	LastSavedAt          time.Time      `json:"last_saved_at"`
}

type InstanceState struct {
	Manifest  *InstanceManifest `json:"manifest,omitempty"`
	Managed   bool              `json:"managed"`
	Status    string            `json:"status"` // enabled|disabled|retired|live_only
	RetiredAt time.Time         `json:"retired_at,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type FeedStats struct {
	TotalLines            int `json:"total_lines"`
	BlankLines            int `json:"blank_lines"`
	CommentLines          int `json:"comment_lines"`
	InvalidFormatLines    int `json:"invalid_format_lines"`
	DuplicateLines        int `json:"duplicate_lines"`
	HardInvalidScopeLines int `json:"hard_invalid_scope_lines"`
	ExpandedFromCIDR      int `json:"expanded_from_cidr"`
	UniqueEndpoints       int `json:"unique_endpoints"`
}
