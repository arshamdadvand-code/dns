package scanner

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/instances/register", s.handleRegister)
	mux.HandleFunc("/v1/instances/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/v1/instances/demand", s.handleDemand)
	mux.HandleFunc("/v1/instances/list", s.handleListInstances)
	mux.HandleFunc("/v1/instances/", s.handleInstanceOps) // /v1/instances/{id}/...
	return mux
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, apiError{Error: "method_not_allowed"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":        true,
		"ready":     s.Ready(),
		"now":       time.Now().Format(time.RFC3339Nano),
		"feed":      s.feedAbsPath,
		"feedStats": s.store.FeedStats,
	})
}

type registerReq struct {
	Instance struct {
		InstanceID       string `json:"instance_id"`
		Domain           string `json:"domain"`
		KeyFingerprint   string `json:"key_fingerprint"`
		EncryptionMethod int    `json:"encryption_method"`
		Intent           string `json:"intent,omitempty"`
	} `json:"instance"`
	ClientID   string          `json:"client_id"`
	TTLSeconds int             `json:"ttl_seconds"`
	Demand     map[string]bool `json:"demand,omitempty"`
}

type registerResp struct {
	Ok         bool   `json:"ok"`
	InstanceID string `json:"instance_id"`
	Status     string `json:"status"`
	LeaseExp   string `json:"lease_expires_at"`
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiError{Error: "method_not_allowed"})
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiError{Error: "bad_json"})
		return
	}
	req.Instance.InstanceID = strings.TrimSpace(req.Instance.InstanceID)
	req.Instance.Domain = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(req.Instance.Domain), "."))
	req.Instance.KeyFingerprint = strings.TrimSpace(strings.ToLower(req.Instance.KeyFingerprint))
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.Instance.InstanceID == "" || req.Instance.Domain == "" || req.Instance.KeyFingerprint == "" || req.ClientID == "" {
		writeJSON(w, 400, apiError{Error: "missing_fields"})
		return
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > 3600 {
		req.TTLSeconds = 120
	}
	m := InstanceManifest{
		InstanceID:       req.Instance.InstanceID,
		Domain:           req.Instance.Domain,
		KeyFingerprint:   req.Instance.KeyFingerprint,
		EncryptionMethod: req.Instance.EncryptionMethod,
		Enabled:          true,
		Intent:           strings.TrimSpace(req.Instance.Intent),
	}
	lease := InstanceLease{
		InstanceID: req.Instance.InstanceID,
		ClientID:   req.ClientID,
		ExpiresAt:  time.Now().Add(time.Duration(req.TTLSeconds) * time.Second),
		Demand:     req.Demand,
	}
	st := s.RegisterLive(m, lease)
	writeJSON(w, 200, registerResp{
		Ok:         true,
		InstanceID: req.Instance.InstanceID,
		Status:     st,
		LeaseExp:   lease.ExpiresAt.Format(time.RFC3339Nano),
	})
}

type heartbeatReq struct {
	InstanceID string `json:"instance_id"`
	ClientID   string `json:"client_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func (s *Service) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiError{Error: "method_not_allowed"})
		return
	}
	var req heartbeatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiError{Error: "bad_json"})
		return
	}
	req.InstanceID = strings.TrimSpace(req.InstanceID)
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.TTLSeconds <= 0 || req.TTLSeconds > 3600 {
		req.TTLSeconds = 120
	}
	if req.InstanceID == "" || req.ClientID == "" {
		writeJSON(w, 400, apiError{Error: "missing_fields"})
		return
	}
	ok := s.RenewLease(req.InstanceID, req.ClientID, time.Duration(req.TTLSeconds)*time.Second)
	writeJSON(w, 200, map[string]any{"ok": ok})
}

type demandReq struct {
	InstanceID string          `json:"instance_id"`
	ClientID   string          `json:"client_id"`
	Demand     map[string]bool `json:"demand"`
}

func (s *Service) handleDemand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiError{Error: "method_not_allowed"})
		return
	}
	var req demandReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiError{Error: "bad_json"})
		return
	}
	req.InstanceID = strings.TrimSpace(req.InstanceID)
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.InstanceID == "" || req.ClientID == "" {
		writeJSON(w, 400, apiError{Error: "missing_fields"})
		return
	}
	ok := s.UpdateDemand(req.InstanceID, req.ClientID, req.Demand)
	writeJSON(w, 200, map[string]any{"ok": ok})
}

func (s *Service) handleListInstances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, apiError{Error: "method_not_allowed"})
		return
	}
	writeJSON(w, 200, s.ListInstances())
}

func (s *Service) handleInstanceOps(w http.ResponseWriter, r *http.Request) {
	// path: /v1/instances/{id}/warm | /summary | /replenish
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/instances/"), "/")
	if len(parts) < 2 {
		writeJSON(w, 404, apiError{Error: "not_found"})
		return
	}
	id := strings.TrimSpace(parts[0])
	op := strings.TrimSpace(parts[1])
	if id == "" {
		writeJSON(w, 400, apiError{Error: "missing_instance_id"})
		return
	}

	switch op {
	case "warm":
		if r.Method != http.MethodGet {
			writeJSON(w, 405, apiError{Error: "method_not_allowed"})
			return
		}
		writeJSON(w, 200, s.GetWarmCandidates(id))
		return
	case "summary":
		if r.Method != http.MethodGet {
			writeJSON(w, 405, apiError{Error: "method_not_allowed"})
			return
		}
		writeJSON(w, 200, s.GetInventorySummary(id))
		return
	case "replenish":
		if r.Method != http.MethodPost {
			writeJSON(w, 405, apiError{Error: "method_not_allowed"})
			return
		}
		s.TriggerReplenish(id)
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	default:
		writeJSON(w, 404, apiError{Error: "not_found"})
		return
	}
}
