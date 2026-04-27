package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"masterdnsvpn-go/internal/config"
)

type scannerIdentity struct {
	InstanceID       string
	Domain           string
	KeyFingerprint   string
	EncryptionMethod int
}

type scannerWarmResp struct {
	InstanceID string `json:"instance_id"`
	Active     []struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"active_ready"`
	Reserve []struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"reserve_ready"`
}

func (c *Client) ensureScannerOnce(ctx context.Context) {
	if c == nil || !c.cfg.ScannerEnabled {
		return
	}
	c.scannerOnce.Do(func() {
		c.scannerAddr = c.cfg.ScannerAddr
		if c.scannerAddr == "" {
			c.scannerAddr = "127.0.0.1:18777"
		}
		c.scannerHTTP = &http.Client{Timeout: 2 * time.Second}
		c.scannerClientID = c.makeScannerClientID()
		c.scannerInstances = c.makeScannerIdentities()
		_ = c.ensureScannerManifestAndKeysFiles()

		// Attempt to connect/spawn and register once at startup.
		_ = c.connectOrSpawnScanner(ctx)
		_ = c.scannerRegisterAll(ctx)
		_ = c.scannerWarmStartAll(ctx)

		// Background heartbeat. Runtime must not die if scanner is down.
		hbCtx, cancel := context.WithCancel(context.Background())
		c.scannerStopHB = cancel
		go c.scannerHeartbeatLoop(hbCtx)
	})
}

func (c *Client) stopScannerHB() {
	if c == nil {
		return
	}
	if c.scannerStopHB != nil {
		c.scannerStopHB()
		c.scannerStopHB = nil
	}
}

func (c *Client) makeScannerClientID() string {
	exe, _ := os.Executable()
	base := filepath.Base(exe)
	sum := sha256.Sum256([]byte(base + fmt.Sprintf(":%d", os.Getpid())))
	return hex.EncodeToString(sum[:])[:12]
}

func (c *Client) makeScannerIdentities() []scannerIdentity {
	if c == nil {
		return nil
	}

	// Legacy single-instance override (kept for backward compatibility).
	if iid := strings.TrimSpace(c.cfg.ScannerInstanceID); iid != "" {
		domain := ""
		if len(c.cfg.Domains) > 0 {
			domain = c.cfg.Domains[0]
		}
		fp := fingerprintKey(c.cfg.EncryptionKey)
		return []scannerIdentity{{
			InstanceID:       iid,
			Domain:           domain,
			KeyFingerprint:   fp,
			EncryptionMethod: c.cfg.DataEncryptionMethod,
		}}
	}

	entries, _, _ := loadDomainKeyring(c.cfg.ConfigDir, c.cfg.DomainKeyringFile)
	byDomain := make(map[string]domainKeyringEntry, len(entries))
	for _, e := range entries {
		if e.Domain == "" {
			continue
		}
		byDomain[e.Domain] = e
	}

	seen := make(map[string]struct{}, len(c.cfg.Domains))
	out := make([]scannerIdentity, 0, len(c.cfg.Domains))
	for _, d := range c.cfg.Domains {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		rawKey := strings.TrimSpace(c.cfg.EncryptionKey)
		method := c.cfg.DataEncryptionMethod
		if e, ok := byDomain[domain]; ok {
			if e.EncryptionMethod >= 0 && e.EncryptionMethod <= 5 {
				method = e.EncryptionMethod
			}
			if e.Key != "" {
				rawKey = e.Key
			} else if e.KeyFile != "" {
				p := e.KeyFile
				if !filepath.IsAbs(p) && c.cfg.ConfigDir != "" {
					p = filepath.Join(c.cfg.ConfigDir, p)
				}
				if b, err := os.ReadFile(p); err == nil {
					rawKey = strings.TrimSpace(string(b))
				}
			}
		}

		fp := fingerprintKey(rawKey)
		out = append(out, scannerIdentity{
			InstanceID:       domain,
			Domain:           domain,
			KeyFingerprint:   fp,
			EncryptionMethod: method,
		})
	}
	return out
}

func fingerprintKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

func (c *Client) scannerURL(path string) string {
	addr := c.scannerAddr
	if addr == "" {
		addr = "127.0.0.1:18777"
	}
	return "http://" + addr + path
}

func (c *Client) scannerHealth(ctx context.Context) bool {
	if c == nil || c.scannerHTTP == nil {
		return false
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.scannerURL("/health"), nil)
	resp, err := c.scannerHTTP.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == 200
}

func (c *Client) connectOrSpawnScanner(ctx context.Context) bool {
	if c == nil || !c.cfg.ScannerEnabled {
		return false
	}
	if c.scannerHealth(ctx) {
		return true
	}
	if !c.cfg.ScannerSpawn {
		return false
	}
	if !isLocalOnlyAddr(c.scannerAddr) {
		return false
	}

	// Spawn scanner locally if absent.
	exePath, err := c.findScannerBinary()
	if err != nil {
		return false
	}
	args := []string{
		"-listen", c.scannerAddr,
		"-store", filepath.Join(c.cfg.ConfigDir, "scanner_store.json"),
		"-manifest", filepath.Join(c.cfg.ConfigDir, "scanner_instances.json"),
		"-keys", filepath.Join(c.cfg.ConfigDir, "scanner_keys.json"),
		"-feed", filepath.Join(c.cfg.ConfigDir, "scanner_feed.txt"),
	}
	cmd := exec.Command(exePath, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
	c.scannerSpawned = true

	// Wait for ready (bounded).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.scannerHealth(ctx) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

func isLocalOnlyAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == "127.0.0.1" || host == "localhost"
}

func (c *Client) findScannerBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	name := "masterdnsvpn-scanner"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	// Fallback: rely on PATH.
	return name, nil
}

func (c *Client) scannerRegisterAll(ctx context.Context) bool {
	if c == nil || c.scannerHTTP == nil {
		return false
	}
	okAny := false
	for _, id := range c.scannerInstances {
		body := map[string]any{
			"instance": map[string]any{
				"instance_id":       id.InstanceID,
				"domain":            id.Domain,
				"key_fingerprint":   id.KeyFingerprint,
				"encryption_method": id.EncryptionMethod,
				"intent":            "",
			},
			"client_id":   c.scannerClientID,
			"ttl_seconds": 120,
			"demand": map[string]bool{
				"warm_start": true,
			},
		}
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.scannerURL("/v1/instances/register"), bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.scannerHTTP.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			okAny = true
		}
	}
	return okAny
}

func (c *Client) scannerWarmStartAll(ctx context.Context) bool {
	if c == nil || c.scannerHTTP == nil {
		return false
	}

	activeByDomain := make(map[string][]config.ResolverAddress, 8)
	reserveByDomain := make(map[string][]config.ResolverAddress, 8)
	okAny := false

	for _, id := range c.scannerInstances {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.scannerURL("/v1/instances/"+id.InstanceID+"/warm"), nil)
		resp, err := c.scannerHTTP.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			continue
		}
		var wr scannerWarmResp
		if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
			_ = resp.Body.Close()
			continue
		}
		_ = resp.Body.Close()

		seen := make(map[string]struct{}, 256)
		a := make([]config.ResolverAddress, 0, len(wr.Active))
		r := make([]config.ResolverAddress, 0, len(wr.Reserve))
		appendEP := func(dst *[]config.ResolverAddress, ip string, port int) {
			if ip == "" || port < 1 {
				return
			}
			k := fmt.Sprintf("%s:%d", ip, port)
			if _, ok := seen[k]; ok {
				return
			}
			seen[k] = struct{}{}
			*dst = append(*dst, config.ResolverAddress{IP: ip, Port: port})
		}
		for _, e := range wr.Active {
			appendEP(&a, e.IP, e.Port)
		}
		for _, e := range wr.Reserve {
			appendEP(&r, e.IP, e.Port)
		}
		if len(a)+len(r) == 0 {
			continue
		}
		okAny = true
		activeByDomain[id.Domain] = a
		reserveByDomain[id.Domain] = r
	}

	if !okAny {
		return false
	}

	c.overrideConnectionsFromScanner(activeByDomain, reserveByDomain, "scanner_warm_multi")
	return true
}

func (c *Client) overrideConnectionsFromScanner(activeByDomain map[string][]config.ResolverAddress, reserveByDomain map[string][]config.ResolverAddress, source string) {
	if c == nil || c.balancer == nil {
		return
	}

	indexByKey := make(map[string]struct{}, 2048)
	connections := make([]Connection, 0, 2048)
	activeKeys := make(map[string]struct{}, 512)

	add := func(domain string, r config.ResolverAddress, isActive bool) {
		if domain == "" || r.IP == "" || r.Port < 1 {
			return
		}
		key := makeConnectionKey(r.IP, r.Port, domain)
		if _, ok := indexByKey[key]; ok {
			return
		}
		indexByKey[key] = struct{}{}
		if isActive {
			activeKeys[key] = struct{}{}
		}
		label := formatResolverEndpoint(r.IP, r.Port)
		connections = append(connections, Connection{
			Domain:        domain,
			Resolver:      r.IP,
			ResolverPort:  r.Port,
			ResolverLabel: label,
			Key:           key,
			IsValid:       false,
		})
		if ip := net.ParseIP(r.IP); ip != nil {
			c.resolverAddrMu.Lock()
			if c.resolverAddrCache == nil {
				c.resolverAddrCache = make(map[string]*net.UDPAddr, 2048)
			}
			c.resolverAddrCache[label] = &net.UDPAddr{IP: ip, Port: r.Port}
			c.resolverAddrMu.Unlock()
		}
	}

	for domain, rs := range activeByDomain {
		for _, r := range rs {
			add(domain, r, true)
		}
	}
	for domain, rs := range reserveByDomain {
		for _, r := range rs {
			add(domain, r, false)
		}
	}

	pointers := make([]*Connection, len(connections))
	for i := range connections {
		pointers[i] = &connections[i]
	}
	c.balancer.SetConnections(pointers)

	for _, conn := range connections {
		c.balancer.SetConnectionValidity(conn.Key, true)
		if _, ok := activeKeys[conn.Key]; !ok {
			c.balancer.SeedConservativeStats(conn.Key)
		}
	}

	if c.ui != nil {
		c.ui.AddSystemEvent("SCAN", fmt.Sprintf("scanner_inventory_apply source=%s domains=%d conns=%d", source, len(activeByDomain), len(connections)))
	}
}

func (c *Client) scannerHeartbeatLoop(ctx context.Context) {
	t := time.NewTicker(40 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.scannerHeartbeatAll(ctx)
			_ = c.scannerDemandAll(ctx)
		}
	}
}

func (c *Client) scannerHeartbeatAll(ctx context.Context) bool {
	if c == nil || c.scannerHTTP == nil {
		return false
	}
	okAny := false
	for _, id := range c.scannerInstances {
		body := map[string]any{
			"instance_id": idOrEmpty(id.InstanceID),
			"client_id":   c.scannerClientID,
			"ttl_seconds": 120,
		}
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.scannerURL("/v1/instances/heartbeat"), bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.scannerHTTP.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			okAny = true
		}
	}
	return okAny
}

func idOrEmpty(s string) string { return strings.TrimSpace(s) }

func (c *Client) scannerDemandAll(ctx context.Context) bool {
	if c == nil || c.scannerHTTP == nil {
		return false
	}
	// Throttle.
	now := time.Now()
	lastUnix := c.scannerLastDemandAt.Load()
	if lastUnix > 0 && now.Sub(time.Unix(0, lastUnix)) < 30*time.Second {
		return false
	}

	snap := c.runtimeControllerSnapshot()
	demand := map[string]bool{}
	if snap.State == "DEGRADED" || snap.State == "CAUTIOUS" {
		demand["instance_unhealthy"] = snap.State == "DEGRADED"
		demand["active_pool_degraded"] = true
	}
	if snap.ReserveCount <= 10 {
		demand["reserve_low"] = true
		demand["need_more_ready_resolvers"] = true
	}
	if len(demand) == 0 {
		return false
	}

	okAny := false
	for _, id := range c.scannerInstances {
		body := map[string]any{
			"instance_id": id.InstanceID,
			"client_id":   c.scannerClientID,
			"demand":      demand,
		}
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.scannerURL("/v1/instances/demand"), bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.scannerHTTP.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			okAny = true
		}
	}
	if okAny {
		c.scannerLastDemandAt.Store(now.UnixNano())
	}
	return okAny
}

func (c *Client) ensureScannerManifestAndKeysFiles() error {
	if c == nil || !c.cfg.ScannerEnabled || c.cfg.ConfigDir == "" {
		return nil
	}
	ids := c.makeScannerIdentities()
	if len(ids) == 0 {
		return nil
	}

	manifestPath := filepath.Join(c.cfg.ConfigDir, "scanner_instances.json")
	keysPath := filepath.Join(c.cfg.ConfigDir, "scanner_keys.json")

	entries, _, _ := loadDomainKeyring(c.cfg.ConfigDir, c.cfg.DomainKeyringFile)
	byDomain := make(map[string]domainKeyringEntry, len(entries))
	for _, e := range entries {
		if e.Domain == "" {
			continue
		}
		byDomain[e.Domain] = e
	}

	keys := make(map[string]string, len(ids))
	manifest := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		rawKey := strings.TrimSpace(c.cfg.EncryptionKey)
		if e, ok := byDomain[id.Domain]; ok {
			if e.Key != "" {
				rawKey = e.Key
			} else if e.KeyFile != "" {
				p := e.KeyFile
				if !filepath.IsAbs(p) && c.cfg.ConfigDir != "" {
					p = filepath.Join(c.cfg.ConfigDir, p)
				}
				if b, err := os.ReadFile(p); err == nil {
					rawKey = strings.TrimSpace(string(b))
				}
			}
		}
		if rawKey != "" {
			keys[id.InstanceID] = rawKey
		}

		manifest = append(manifest, map[string]any{
			"instance_id":       id.InstanceID,
			"domain":            id.Domain,
			"key_fingerprint":   id.KeyFingerprint,
			"encryption_method": id.EncryptionMethod,
			"enabled":           true,
			"intent":            "",
		})
	}

	if b, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		_ = os.WriteFile(manifestPath, b, 0644)
	}
	if b, err := json.MarshalIndent(keys, "", "  "); err == nil {
		_ = os.WriteFile(keysPath, b, 0600)
	}
	return nil
}
