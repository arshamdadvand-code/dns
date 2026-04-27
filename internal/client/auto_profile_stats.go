// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"sort"
	"sync"
	"time"

	"masterdnsvpn-go/internal/config"
)

type autoProfileResolverMini struct {
	addr      string
	stage0OK  bool
	upRec     int
	downRec   int
	upMax     int
	downMax   int
	active    bool
	reserve   bool
	failStage string
}

type autoProfileRunStats struct {
	mu sync.Mutex

	startedAt time.Time
	domain    string

	// Resolver file stats (labels must be explicit: blank/invalid/dup/scope).
	resolverFile config.ResolverFileStats

	// Stage counters.
	totalUniqueInput int

	stage0Attempted int
	stage0Viable    int
	stage0Timeout   int
	stage0Malformed int

	stage1UploadWorking int
	stage1UploadFail    int
	stage1DownloadWorking int
	stage1DownloadFail    int

	stage2Refined      int
	profileComplete    int

	// Reasons.
	stage0MalformedSub map[string]int
	stage1FailReasons  map[string]int

	// Mini spectrum store (only for Stage0 survivors, so small).
	survivors []autoProfileResolverMini

	// Derived runtime snapshot.
	derivedAvailable bool
	derivedUpload    int
	derivedDownload  int
	derivedActive    int
	derivedReserve   int
	derivedSetupDup  int
	derivedDataDup   int
	derivedFailThr   int
	derivedFailCool  float64
	derivedConfidence string
	derivedFragile    bool
	derivedActiveList []string
	derivedReserveList []string

	eventSink *tuiEventSink

	// Finalization
	completed      bool
	completedAt    time.Time
	persistedPath  string
}

func newAutoProfileRunStats(domain string, resolverStats config.ResolverFileStats, uniqueInput int) *autoProfileRunStats {
	return &autoProfileRunStats{
		startedAt:        time.Now(),
		domain:           domain,
		resolverFile:     resolverStats,
		totalUniqueInput: uniqueInput,
		stage0MalformedSub: map[string]int{},
		stage1FailReasons:  map[string]int{},
		survivors:          make([]autoProfileResolverMini, 0, 128),
	}
}

func (s *autoProfileRunStats) attachEventSink(sink *tuiEventSink) {
	s.mu.Lock()
	s.eventSink = sink
	s.mu.Unlock()
}

func (s *autoProfileRunStats) incStage0Attempted() {
	s.mu.Lock()
	s.stage0Attempted++
	s.mu.Unlock()
}

func (s *autoProfileRunStats) recordStage0Result(ok bool, failReason string, malformedSub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.stage0Viable++
		return
	}
	switch failReason {
	case "STAGE0_TIMEOUT":
		s.stage0Timeout++
	case "STAGE0_MALFORMED":
		s.stage0Malformed++
		if malformedSub == "" {
			malformedSub = "(unknown)"
		}
		s.stage0MalformedSub[malformedSub] = s.stage0MalformedSub[malformedSub] + 1
	default:
		// Treat other Stage0 failures as malformed bucket for Phase 1 accounting.
		s.stage0Malformed++
		if malformedSub == "" {
			malformedSub = failReason
		}
		s.stage0MalformedSub[malformedSub] = s.stage0MalformedSub[malformedSub] + 1
	}
}

func (s *autoProfileRunStats) recordStage1Upload(ok bool, fail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.stage1UploadWorking++
		return
	}
	s.stage1UploadFail++
	if fail == "" {
		fail = "(unknown)"
	}
	s.stage1FailReasons[fail] = s.stage1FailReasons[fail] + 1
}

func (s *autoProfileRunStats) recordStage1Download(ok bool, fail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.stage1DownloadWorking++
		return
	}
	s.stage1DownloadFail++
	if fail == "" {
		fail = "(unknown)"
	}
	s.stage1FailReasons[fail] = s.stage1FailReasons[fail] + 1
}

func (s *autoProfileRunStats) recordStage2Refined() {
	s.mu.Lock()
	s.stage2Refined++
	s.mu.Unlock()
}

func (s *autoProfileRunStats) recordProfileComplete() {
	s.mu.Lock()
	s.profileComplete++
	s.mu.Unlock()
}

func (s *autoProfileRunStats) upsertSurvivor(mini autoProfileResolverMini) {
	s.mu.Lock()
	s.survivors = append(s.survivors, mini)
	s.mu.Unlock()
}

func (s *autoProfileRunStats) setDerivedSnapshot(upload, download int, activeList, reserveList []string, setupDup, dataDup, failThr int, failCool float64, confidence string, fragile bool) {
	s.mu.Lock()
	s.derivedAvailable = true
	s.derivedUpload = upload
	s.derivedDownload = download
	s.derivedActive = len(activeList)
	s.derivedReserve = len(reserveList)
	s.derivedSetupDup = setupDup
	s.derivedDataDup = dataDup
	s.derivedFailThr = failThr
	s.derivedFailCool = failCool
	s.derivedConfidence = confidence
	s.derivedFragile = fragile
	s.derivedActiveList = append([]string(nil), activeList...)
	s.derivedReserveList = append([]string(nil), reserveList...)
	s.mu.Unlock()
}

type autoProfileSnapshot struct {
	Domain string
	Elapsed time.Duration

	File config.ResolverFileStats
	UniqueInput int

	Stage0Attempted int
	Stage0Viable int
	Stage0Timeout int
	Stage0Malformed int

	Stage1UploadWorking int
	Stage1UploadFail int
	Stage1DownloadWorking int
	Stage1DownloadFail int

	Stage2Refined int
	ProfileComplete int

	MalformedSubTop []kv
	StageFailTop []kv

	Survivors []autoProfileResolverMini

	DerivedAvailable bool
	DerivedUpload int
	DerivedDownload int
	DerivedActive int
	DerivedReserve int
	DerivedSetupDup int
	DerivedDataDup int
	DerivedFailThr int
	DerivedFailCool float64
	DerivedConfidence string
	DerivedFragile bool
	DerivedActiveList []string
	DerivedReserveList []string

	Events []tuiEvent

	Completed   bool
	CompletedAt time.Time
	PersistedPath string
}

type kv struct {
	k string
	v int
}

func (s *autoProfileRunStats) snapshot() autoProfileSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := autoProfileSnapshot{
		Domain: s.domain,
		Elapsed: time.Since(s.startedAt),
		File: s.resolverFile,
		UniqueInput: s.totalUniqueInput,

		Stage0Attempted: s.stage0Attempted,
		Stage0Viable: s.stage0Viable,
		Stage0Timeout: s.stage0Timeout,
		Stage0Malformed: s.stage0Malformed,

		Stage1UploadWorking: s.stage1UploadWorking,
		Stage1UploadFail: s.stage1UploadFail,
		Stage1DownloadWorking: s.stage1DownloadWorking,
		Stage1DownloadFail: s.stage1DownloadFail,

		Stage2Refined: s.stage2Refined,
		ProfileComplete: s.profileComplete,

		Survivors: append([]autoProfileResolverMini(nil), s.survivors...),

		DerivedAvailable: s.derivedAvailable,
		DerivedUpload: s.derivedUpload,
		DerivedDownload: s.derivedDownload,
		DerivedActive: s.derivedActive,
		DerivedReserve: s.derivedReserve,
		DerivedSetupDup: s.derivedSetupDup,
		DerivedDataDup: s.derivedDataDup,
		DerivedFailThr: s.derivedFailThr,
		DerivedFailCool: s.derivedFailCool,
		DerivedConfidence: s.derivedConfidence,
		DerivedFragile: s.derivedFragile,
		DerivedActiveList: append([]string(nil), s.derivedActiveList...),
		DerivedReserveList: append([]string(nil), s.derivedReserveList...),
	}

	if s.eventSink != nil {
		out.Events = s.eventSink.snapshot(8)
	}

	out.Completed = s.completed
	out.CompletedAt = s.completedAt
	out.PersistedPath = s.persistedPath

	out.MalformedSubTop = topK(s.stage0MalformedSub, 8)
	out.StageFailTop = topK(s.stage1FailReasons, 8)
	return out
}

func (s *autoProfileRunStats) markCompleted(persistedPath string) {
	s.mu.Lock()
	s.completed = true
	s.completedAt = time.Now()
	s.persistedPath = persistedPath
	s.mu.Unlock()
}

func topK(m map[string]int, k int) []kv {
	if len(m) == 0 || k <= 0 {
		return nil
	}
	out := make([]kv, 0, len(m))
	for key, val := range m {
		out = append(out, kv{k: key, v: val})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	if len(out) > k {
		out = out[:k]
	}
	return out
}
