package scanner

type Config struct {
	ListenAddr   string
	StorePath    string
	ManifestPath string
	FeedPath     string
	KeysPath     string

	// Phase-aware bounded concurrency. These are intentionally explicit; the scanner
	// must not be effectively serial when working large feeds.
	ConcurrencyBaseProbe       int
	ConcurrencyOverlayValidate int
	ConcurrencyReplenish       int
	ConcurrencyExpand          int
	ConcurrencyMaintenance     int
}
