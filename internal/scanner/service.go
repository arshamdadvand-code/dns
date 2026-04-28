package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"masterdnsvpn-go/internal/client"
)

const (
	defaultLeaseTTL      = 120 * time.Second
	retireGracePeriod    = 12 * time.Hour
	overlayReadyMaxAge   = 45 * time.Minute
	maintenanceTick      = 12 * time.Second
	inventoryRefreshTick = 30 * time.Second
	maxWarmReturn        = 128
)

type Service struct {
	cfg Config

	mu sync.RWMutex

	store      *Store
	storeDirty bool
	ready      bool

	feedAbsPath string
	feed        []Endpoint

	leases      map[string]map[string]InstanceLease // instance_id -> client_id -> lease
	manifest    map[string]InstanceManifest
	keyring     map[string]string
	keysAbsPath string

	probers map[string]*client.InventoryProber // instance_id -> prober

	replenishRequests map[string]time.Time
}

func NewService(cfg Config) (*Service, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:18777"
	}
	if cfg.StorePath == "" {
		cfg.StorePath = "scanner_store.json"
	}
	if cfg.ManifestPath == "" {
		cfg.ManifestPath = "scanner_instances.json"
	}
	if cfg.FeedPath == "" {
		cfg.FeedPath = "scanner_feed.txt"
	}
	if cfg.KeysPath == "" {
		cfg.KeysPath = "scanner_keys.json"
	}
	if cfg.ConcurrencyBaseProbe <= 0 {
		cfg.ConcurrencyBaseProbe = 100
	}
	if cfg.ConcurrencyOverlayValidate <= 0 {
		cfg.ConcurrencyOverlayValidate = 32
	}
	if cfg.ConcurrencyReplenish <= 0 {
		cfg.ConcurrencyReplenish = 64
	}
	if cfg.ConcurrencyExpand <= 0 {
		cfg.ConcurrencyExpand = 100
	}
	if cfg.ConcurrencyMaintenance <= 0 {
		cfg.ConcurrencyMaintenance = 16
	}

	st, err := loadStore(cfg.StorePath)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:               cfg,
		store:             st,
		leases:            make(map[string]map[string]InstanceLease),
		manifest:          make(map[string]InstanceManifest),
		keyring:           make(map[string]string),
		probers:           make(map[string]*client.InventoryProber),
		replenishRequests: make(map[string]time.Time),
	}, nil
}

func (s *Service) probeMany(ctx context.Context, instanceID string, eps []Endpoint, conc int) {
	if len(eps) == 0 {
		return
	}
	if conc < 1 {
		conc = 1
	}
	if conc > len(eps) {
		conc = len(eps)
	}
	if conc <= 1 {
		for _, ep := range eps {
			if ctx.Err() != nil {
				return
			}
			s.probeOne(ctx, instanceID, ep)
		}
		return
	}

	ch := make(chan Endpoint)
	var wg sync.WaitGroup
	wg.Add(conc)
	for i := 0; i < conc; i++ {
		go func() {
			defer wg.Done()
			for ep := range ch {
				if ctx.Err() != nil {
					return
				}
				s.probeOne(ctx, instanceID, ep)
			}
		}()
	}
	for _, ep := range eps {
		if ctx.Err() != nil {
			break
		}
		ch <- ep
	}
	close(ch)
	wg.Wait()
}

func (s *Service) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

func (s *Service) Start(ctx context.Context) error {
	// Load feed + manifest; reconcile store instances.
	if err := s.reloadManifestLocked(); err != nil {
		return err
	}
	if err := s.reloadKeyringLocked(); err != nil {
		return err
	}
	if err := s.reloadFeedLocked(); err != nil {
		return err
	}
	s.reconcileInstancesLocked()

	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()

	go s.loopSave(ctx)
	go s.loopMaintenance(ctx)
	go s.loopInventory(ctx)
	// Kick one inventory step immediately so a freshly started scanner can become
	// operational without waiting for the first ticker tick.
	go s.inventoryStep(ctx)
	return nil
}

func (s *Service) reloadFeedLocked() error {
	f, err := loadFeed(s.cfg.FeedPath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.feedAbsPath = f.AbsPath
	s.feed = f.Endpoints
	s.store.FeedStats = f.Stats
	s.storeDirty = true
	s.mu.Unlock()
	return nil
}

func (s *Service) reloadManifestLocked() error {
	m, err := loadManifest(s.cfg.ManifestPath)
	if err != nil {
		return err
	}
	mp := make(map[string]InstanceManifest, len(m))
	for _, it := range m {
		if it.InstanceID == "" || it.Domain == "" || it.KeyFingerprint == "" {
			continue
		}
		mp[it.InstanceID] = it
	}
	s.mu.Lock()
	s.manifest = mp
	s.storeDirty = true
	s.mu.Unlock()
	return nil
}

func (s *Service) reloadKeyringLocked() error {
	m, abs, err := loadKeyring(s.cfg.KeysPath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keyring = m
	s.keysAbsPath = abs
	s.storeDirty = true
	s.mu.Unlock()
	return nil
}

func (s *Service) reconcileInstancesLocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	// Update/insert manifest instances.
	for id, m := range s.manifest {
		st := s.store.Instances[id]
		st.Manifest = &m
		st.Managed = true
		if !m.Enabled {
			st.Status = "disabled"
		} else {
			if st.Status == "" || st.Status == "retired" {
				st.Status = "enabled"
				st.RetiredAt = time.Time{}
			}
		}
		st.UpdatedAt = now
		s.store.Instances[id] = st
		s.ensureProberLocked(m)
	}

	// Retire unknown instances (keep overlays, TTL-based cleanup).
	for id, st := range s.store.Instances {
		if _, ok := s.manifest[id]; ok {
			continue
		}
		// If it was managed (previously in desired manifest), removal means retire even if a client is still alive.
		if st.Managed {
			if st.Status != "retired" {
				st.Status = "retired"
				st.RetiredAt = now
				st.UpdatedAt = now
				s.store.Instances[id] = st
			}
			continue
		}

		// Live-only instances can exist while leases are active; they are retired after leases expire.
		if s.leases[id] != nil && len(s.leases[id]) > 0 {
			if st.Status == "" {
				st.Status = "live_only"
				st.UpdatedAt = now
				s.store.Instances[id] = st
			}
			continue
		}
		if st.Status != "retired" {
			st.Status = "retired"
			st.RetiredAt = now
			st.UpdatedAt = now
			s.store.Instances[id] = st
		}
	}
}

func (s *Service) ensureProberLocked(m InstanceManifest) {
	if p := s.probers[m.InstanceID]; p != nil {
		return
	}
	raw, ok := s.keyring[m.InstanceID]
	if !ok || strings.TrimSpace(raw) == "" {
		return
	}
	if FingerprintKey(raw) != strings.ToLower(strings.TrimSpace(m.KeyFingerprint)) {
		// key mismatch: do not probe
		return
	}
	p, err := client.NewInventoryProber(m.Domain, m.EncryptionMethod, raw)
	if err != nil {
		return
	}
	s.probers[m.InstanceID] = p
}

func (s *Service) loopSave(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flushSave()
			return
		case <-t.C:
			s.flushSave()
		}
	}
}

func (s *Service) flushSave() {
	s.mu.Lock()
	dirty := s.storeDirty
	s.storeDirty = false
	st := s.cloneStoreLocked()
	s.mu.Unlock()
	if !dirty {
		return
	}
	_ = saveStore(s.cfg.StorePath, st)
}

func (s *Service) cloneStoreLocked() *Store {
	if s.store == nil {
		return &Store{Version: storeVersion}
	}
	src := s.store
	dst := &Store{
		Version:              src.Version,
		FeedStats:            src.FeedStats,
		LastSavedAt:          src.LastSavedAt,
		BaseCandidates:       make(map[string]BaseCandidate, len(src.BaseCandidates)),
		Overlays:             make(map[string]map[string]InstanceOverlay, len(src.Overlays)),
		Instances:            make(map[string]InstanceState, len(src.Instances)),
		FeedCursorByInstance: make(map[string]int, len(src.FeedCursorByInstance)),
	}
	for k, v := range src.BaseCandidates {
		dst.BaseCandidates[k] = v
	}
	for iid, m := range src.Overlays {
		nm := make(map[string]InstanceOverlay, len(m))
		for k, v := range m {
			nm[k] = v
		}
		dst.Overlays[iid] = nm
	}
	for k, v := range src.Instances {
		dst.Instances[k] = v
	}
	for k, v := range src.FeedCursorByInstance {
		dst.FeedCursorByInstance[k] = v
	}
	return dst
}

func (s *Service) loopMaintenance(ctx context.Context) {
	t := time.NewTicker(maintenanceTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepLeases()
			_ = s.reloadManifestLocked()
			_ = s.reloadKeyringLocked()
			s.reconcileInstancesLocked()
		}
	}
}

func (s *Service) sweepLeases() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for iid, byClient := range s.leases {
		for cid, l := range byClient {
			if now.After(l.ExpiresAt) {
				delete(byClient, cid)
			}
		}
		if len(byClient) == 0 {
			delete(s.leases, iid)
		}
	}

	// Retired TTL cleanup: do not hard-delete immediately.
	for id, st := range s.store.Instances {
		if st.Status != "retired" || st.RetiredAt.IsZero() {
			continue
		}
		if now.Sub(st.RetiredAt) < retireGracePeriod {
			continue
		}
		// Keep base candidates; drop overlays for fully retired instances after grace.
		delete(s.store.Overlays, id)
		delete(s.store.Instances, id)
		delete(s.probers, id)
		delete(s.replenishRequests, id)
		s.storeDirty = true
	}
}

func (s *Service) loopInventory(ctx context.Context) {
	t := time.NewTicker(inventoryRefreshTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.inventoryStep(ctx)
		}
	}
}

func (s *Service) inventoryStep(ctx context.Context) {
	now := time.Now()

	// Snapshot instances to act on.
	s.mu.RLock()
	instances := make([]string, 0, len(s.store.Instances))
	for id, st := range s.store.Instances {
		if st.Status != "enabled" && st.Status != "live_only" {
			continue
		}
		instances = append(instances, id)
	}
	reqs := make(map[string]time.Time, len(s.replenishRequests))
	for k, v := range s.replenishRequests {
		reqs[k] = v
	}
	s.mu.RUnlock()

	for _, iid := range instances {
		if ctx.Err() != nil {
			return
		}
		// Inventory-first:
		// - If we have enough ready candidates, just refresh a small sample.
		// - If demand exists (or ready is low), replenish from cold-known then expand from feed.
		s.stepInstance(ctx, now, iid, reqs[iid])
	}
}

func (s *Service) stepInstance(ctx context.Context, now time.Time, instanceID string, demandAt time.Time) {
	p := s.getProber(instanceID)
	if p == nil {
		return
	}

	ready, cold, blocked := s.countBuckets(instanceID, now)
	need := ready < 48 || (!demandAt.IsZero() && now.Sub(demandAt) < 5*time.Minute)
	if !need {
		// Maintenance: refresh a tiny random sample of ready.
		s.refreshSample(ctx, instanceID, 2)
		s.rebalanceReadyBuckets(instanceID)
		return
	}

	// Replenish: revive cold-known first.
	if ready < 48 && cold > 0 {
		n := 64
		if ready == 0 {
			n = 512
		} else if ready < 8 {
			n = 256
		} else if ready < 24 {
			n = 128
		}
		if cold < n {
			n = cold
		}
		s.probeFromBucket(ctx, instanceID, BucketColdKnown, n)
		ready, _, blocked = s.countBuckets(instanceID, now)
		_ = blocked
		if ready >= 48 {
			return
		}
	}

	// Expand/world scan: probe new endpoints from feed (bounded).
	n := 256
	if ready == 0 {
		n = 4096
	} else if ready < 8 {
		n = 1024
	} else if ready < 24 {
		n = 512
	}
	s.expandFromFeed(ctx, instanceID, n)
	s.rebalanceReadyBuckets(instanceID)
}

// rebalanceReadyBuckets maintains a small "active_ready" head and a larger "reserve_ready" tail.
// This is inventory-only labeling (not runtime routing control).
func (s *Service) rebalanceReadyBuckets(instanceID string) {
	const activeHead = 8
	now := time.Now()

	type scored struct {
		key   string
		score float64
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ov := s.store.Overlays[instanceID]
	if ov == nil {
		return
	}
	ready := make([]scored, 0, 64)
	for k, o := range ov {
		if o.Bucket != BucketReserveReady && o.Bucket != BucketActiveReady {
			continue
		}
		if o.LastValidatedAt.IsZero() || now.Sub(o.LastValidatedAt) > overlayReadyMaxAge {
			continue
		}
		okRatio := float64(o.OKCount) / float64(maxInt(1, o.OKCount+o.FailCount))
		score := okRatio
		if o.LastRTTms > 0 {
			score -= minFloat(0.30, o.LastRTTms/3000.0)
		}
		ready = append(ready, scored{key: k, score: score})
	}
	if len(ready) == 0 {
		return
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].score > ready[j].score })

	activeSet := make(map[string]struct{}, activeHead)
	for i := 0; i < len(ready) && i < activeHead; i++ {
		activeSet[ready[i].key] = struct{}{}
	}

	changed := false
	for k, o := range ov {
		if o.Bucket != BucketReserveReady && o.Bucket != BucketActiveReady {
			continue
		}
		_, wantActive := activeSet[k]
		if wantActive && o.Bucket != BucketActiveReady {
			o.Bucket = BucketActiveReady
			ov[k] = o
			changed = true
		}
		if !wantActive && o.Bucket != BucketReserveReady {
			o.Bucket = BucketReserveReady
			ov[k] = o
			changed = true
		}
	}
	if changed {
		s.storeDirty = true
	}
}

func (s *Service) getProber(instanceID string) *client.InventoryProber {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.probers[instanceID]
}

func (s *Service) countBuckets(instanceID string, now time.Time) (ready int, cold int, blocked int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ov := s.store.Overlays[instanceID]
	if ov == nil {
		return 0, 0, 0
	}
	for _, o := range ov {
		switch o.Bucket {
		case BucketActiveReady, BucketReserveReady:
			if !o.LastValidatedAt.IsZero() && now.Sub(o.LastValidatedAt) <= overlayReadyMaxAge {
				ready++
			} else {
				cold++
			}
		case BucketColdKnown:
			cold++
		case BucketCarrierBlocked:
			blocked++
		}
	}
	return ready, cold, blocked
}

func (s *Service) refreshSample(ctx context.Context, instanceID string, n int) {
	cands := s.listBucket(instanceID, BucketReserveReady)
	if len(cands) == 0 {
		cands = s.listBucket(instanceID, BucketActiveReady)
	}
	if len(cands) == 0 {
		return
	}
	rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	if n > len(cands) {
		n = len(cands)
	}
	s.probeMany(ctx, instanceID, cands[:n], s.cfg.ConcurrencyMaintenance)
}

func (s *Service) probeFromBucket(ctx context.Context, instanceID string, b OverlayBucket, n int) {
	cands := s.listBucket(instanceID, b)
	if len(cands) == 0 {
		return
	}
	rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	if n > len(cands) {
		n = len(cands)
	}
	conc := s.cfg.ConcurrencyOverlayValidate
	if b == BucketColdKnown {
		conc = s.cfg.ConcurrencyReplenish
	}
	s.probeMany(ctx, instanceID, cands[:n], conc)
}

func (s *Service) listBucket(instanceID string, b OverlayBucket) []Endpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ov := s.store.Overlays[instanceID]
	if ov == nil {
		return nil
	}
	out := make([]Endpoint, 0, 64)
	for _, o := range ov {
		if o.Bucket == b {
			out = append(out, o.Endpoint)
		}
	}
	return out
}

func (s *Service) expandFromFeed(ctx context.Context, instanceID string, n int) {
	s.mu.RLock()
	feed := append([]Endpoint(nil), s.feed...)
	ov := s.store.Overlays[instanceID]
	existing := make(map[string]struct{}, len(ov))
	for k := range ov {
		existing[k] = struct{}{}
	}
	cursor := 0
	if s.store.FeedCursorByInstance != nil {
		cursor = s.store.FeedCursorByInstance[instanceID]
	}
	s.mu.RUnlock()
	if len(feed) == 0 {
		return
	}
	if n > len(feed) {
		n = len(feed)
	}

	if cursor < 0 {
		cursor = 0
	}
	cursor = cursor % len(feed)
	picked := make([]Endpoint, 0, n)

	// Fair bounded traversal: walk forward from the persisted cursor and wrap around.
	// We move the cursor regardless of whether we pick the endpoint so we don't get
	// trapped on a hot/duplicate region.
	attempts := 0
	i := cursor
	for len(picked) < n && attempts < len(feed) {
		if ctx.Err() != nil {
			return
		}
		ep := feed[i]
		k := ep.Key()
		if _, ok := existing[k]; !ok {
			existing[k] = struct{}{}
			picked = append(picked, ep)
		}
		i++
		if i >= len(feed) {
			i = 0
		}
		attempts++
	}

	// Persist cursor progress.
	s.mu.Lock()
	if s.store.FeedCursorByInstance == nil {
		s.store.FeedCursorByInstance = make(map[string]int)
	}
	s.store.FeedCursorByInstance[instanceID] = i
	s.storeDirty = true
	s.mu.Unlock()

	if len(picked) == 0 {
		return
	}
	for _, ep := range picked {
		s.addBaseCandidate(ep, "feed:"+s.feedAbsPath)
		s.seedOverlay(instanceID, ep)
	}
	s.probeMany(ctx, instanceID, picked, s.cfg.ConcurrencyExpand)
}

func (s *Service) addBaseCandidate(ep Endpoint, source string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ep.Key()
	b, ok := s.store.BaseCandidates[k]
	if !ok {
		s.store.BaseCandidates[k] = BaseCandidate{
			Endpoint:    ep,
			FirstSeenAt: now,
			LastSeenAt:  now,
			Source:      source,
		}
		s.storeDirty = true
		return
	}
	b.LastSeenAt = now
	if b.Source == "" {
		b.Source = source
	}
	s.store.BaseCandidates[k] = b
	s.storeDirty = true
}

func (s *Service) seedOverlay(instanceID string, ep Endpoint) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store.Overlays[instanceID] == nil {
		s.store.Overlays[instanceID] = make(map[string]InstanceOverlay)
	}
	k := ep.Key()
	if _, ok := s.store.Overlays[instanceID][k]; ok {
		return
	}
	s.store.Overlays[instanceID][k] = InstanceOverlay{
		InstanceID:  instanceID,
		Endpoint:    ep,
		Bucket:      BucketColdKnown,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	s.storeDirty = true
}

func (s *Service) probeOne(ctx context.Context, instanceID string, ep Endpoint) {
	p := s.getProber(instanceID)
	if p == nil {
		return
	}
	// Scanner probing is inventory-first and often operates in sparse environments.
	// A slightly longer timeout improves parity with real-world conditions and
	// reduces false negatives during cold-start.
	res, prof, err := p.ProfileResult(ctx, ep.IP, ep.Port, 4*time.Second)
	_ = err
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store.Overlays[instanceID] == nil {
		s.store.Overlays[instanceID] = make(map[string]InstanceOverlay)
	}
	k := ep.Key()
	o := s.store.Overlays[instanceID][k]
	o.InstanceID = instanceID
	o.Endpoint = ep
	o.LastSeenAt = now
	o.LastValidatedAt = now
	o.LastResult = res.FailReason
	o.LastSubReason = res.SubReason
	o.LastRTTms = res.RTTms
	o.ProfileComplete = false
	o.UploadRecBytes = 0
	o.UploadMaxBytes = 0
	o.DownloadRecBytes = 0
	o.DownloadMaxBytes = 0
	if prof != nil {
		o.ProfileComplete = prof.Viability.Status == "viable" && prof.Upload.RecommendedBytes > 0 && prof.Download.RecommendedBytes > 0
		o.UploadRecBytes = prof.Upload.RecommendedBytes
		o.UploadMaxBytes = prof.Upload.WorkingMaxBytes
		o.DownloadRecBytes = prof.Download.RecommendedBytes
		o.DownloadMaxBytes = prof.Download.WorkingMaxBytes
	}
	if res.OK {
		o.OKCount++
		// Scanner parity: only profile-complete resolvers become ready inventory.
		if o.ProfileComplete && o.Bucket != BucketActiveReady {
			o.Bucket = BucketReserveReady
		} else if !o.ProfileComplete {
			o.Bucket = BucketColdKnown
		}
		o.QuarantineUntil = time.Time{}
	} else {
		o.FailCount++
		up := strings.ToUpper(res.SubReason)
		if containsCarrierBlock(up) {
			o.Bucket = BucketCarrierBlocked
			o.QuarantineUntil = now.Add(4 * time.Minute)
		} else {
			o.Bucket = BucketColdKnown
		}
	}
	s.store.Overlays[instanceID][k] = o
	s.storeDirty = true
}

func containsCarrierBlock(u string) bool {
	// Match Stage0 subreason classification used elsewhere.
	return strings.Contains(u, "DNS_RCODE_REFUSED") || strings.Contains(u, "DNS_RCODE_SERVFAIL") ||
		strings.Contains(u, "REFUSED") || strings.Contains(u, "SERVFAIL")
}

func (s *Service) RegisterLive(inst InstanceManifest, lease InstanceLease) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	// Ensure instance record exists; manifest remains desired truth, but live registrations
	// are allowed (live_only) so scanner can stop/start for newly added instances.
	st := s.store.Instances[inst.InstanceID]
	if st.Manifest == nil {
		// No desired manifest entry: keep as live_only.
		i := inst
		st.Manifest = &i
		st.Status = "live_only"
		st.Managed = false
		st.UpdatedAt = now
		s.store.Instances[inst.InstanceID] = st
	}
	if s.leases[inst.InstanceID] == nil {
		s.leases[inst.InstanceID] = make(map[string]InstanceLease)
	}
	s.leases[inst.InstanceID][lease.ClientID] = lease
	if st.Manifest != nil {
		s.ensureProberLocked(*st.Manifest)
	}

	s.storeDirty = true
	return st.Status
}

func (s *Service) RenewLease(instanceID, clientID string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	byClient := s.leases[instanceID]
	if byClient == nil {
		return false
	}
	l, ok := byClient[clientID]
	if !ok {
		return false
	}
	if ttl <= 0 {
		ttl = defaultLeaseTTL
	}
	l.ExpiresAt = time.Now().Add(ttl)
	byClient[clientID] = l
	s.storeDirty = true
	return true
}

func (s *Service) UpdateDemand(instanceID, clientID string, demand map[string]bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	byClient := s.leases[instanceID]
	if byClient == nil {
		return false
	}
	l, ok := byClient[clientID]
	if !ok {
		return false
	}
	l.Demand = demand
	byClient[clientID] = l
	s.replenishRequests[instanceID] = time.Now()
	s.storeDirty = true
	return true
}

func (s *Service) TriggerReplenish(instanceID string) {
	s.mu.Lock()
	s.replenishRequests[instanceID] = time.Now()
	s.storeDirty = true
	s.mu.Unlock()
}

func (s *Service) ListInstances() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]map[string]any, 0, len(s.store.Instances))
	for id, st := range s.store.Instances {
		leaseCount := 0
		if s.leases[id] != nil {
			leaseCount = len(s.leases[id])
		}
		out = append(out, map[string]any{
			"instance_id": id,
			"status":      st.Status,
			"enabled":     st.Manifest != nil && st.Manifest.Enabled,
			"domain": safeStr(func() string {
				if st.Manifest != nil {
					return st.Manifest.Domain
				}
				return ""
			}()),
			"key_fp": safeStr(func() string {
				if st.Manifest != nil {
					return st.Manifest.KeyFingerprint
				}
				return ""
			}()),
			"leases":     leaseCount,
			"updated_at": st.UpdatedAt.Format(time.RFC3339Nano),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["instance_id"].(string) < out[j]["instance_id"].(string)
	})
	return map[string]any{"instances": out}
}

func safeStr(s string) string { return s }

type warmResp struct {
	InstanceID string     `json:"instance_id"`
	Active     []Endpoint `json:"active_ready"`
	Reserve    []Endpoint `json:"reserve_ready"`
	ColdKnown  int        `json:"cold_known_count"`
	Blocked    int        `json:"carrier_blocked_count"`
}

func (s *Service) GetWarmCandidates(instanceID string) warmResp {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	ov := s.store.Overlays[instanceID]
	resp := warmResp{InstanceID: instanceID}
	if ov == nil {
		return resp
	}

	type scored struct {
		ep    Endpoint
		score float64
		rtt   float64
	}
	active := make([]scored, 0, 16)
	reserve := make([]scored, 0, 128)
	for _, o := range ov {
		if o.Bucket == BucketCarrierBlocked {
			resp.Blocked++
			continue
		}
		if o.Bucket == BucketColdKnown || o.LastValidatedAt.IsZero() || now.Sub(o.LastValidatedAt) > overlayReadyMaxAge {
			resp.ColdKnown++
			continue
		}
		okRatio := float64(o.OKCount) / float64(maxInt(1, o.OKCount+o.FailCount))
		score := okRatio
		if o.LastRTTms > 0 {
			score -= minFloat(0.30, o.LastRTTms/3000.0)
		}
		item := scored{ep: o.Endpoint, score: score, rtt: o.LastRTTms}
		if o.Bucket == BucketActiveReady {
			active = append(active, item)
		} else {
			reserve = append(reserve, item)
		}
	}

	sort.Slice(active, func(i, j int) bool { return active[i].score > active[j].score })
	sort.Slice(reserve, func(i, j int) bool { return reserve[i].score > reserve[j].score })

	for i := 0; i < len(active) && i < maxWarmReturn; i++ {
		resp.Active = append(resp.Active, active[i].ep)
	}
	for i := 0; i < len(reserve) && i < maxWarmReturn; i++ {
		resp.Reserve = append(resp.Reserve, reserve[i].ep)
	}
	return resp
}

func (s *Service) GetInventorySummary(instanceID string) map[string]any {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	ov := s.store.Overlays[instanceID]
	if ov == nil {
		return map[string]any{"instance_id": instanceID}
	}
	buckets := map[string]int{}
	ready := 0
	for _, o := range ov {
		buckets[string(o.Bucket)]++
		if (o.Bucket == BucketActiveReady || o.Bucket == BucketReserveReady) &&
			!o.LastValidatedAt.IsZero() && now.Sub(o.LastValidatedAt) <= overlayReadyMaxAge {
			ready++
		}
	}
	return map[string]any{
		"instance_id":   instanceID,
		"ready_count":   ready,
		"bucket_counts": buckets,
		"base_count":    len(s.store.BaseCandidates),
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// Instance identity helpers for operators.
func FingerprintKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}
