# MasterDnsVPN Continuation Handoff

## Purpose

This document is the current engineering handoff for the modified `MasterDnsVPN` codebase in `C:\dns`.

It is intended for any future engineer, operator, or agent who needs to continue the work without reconstructing the entire history from prompts, logs, and partial artifacts.

This document focuses on:

- the intended product direction
- what was implemented
- what was verified
- what is only present in code but not yet proven end-to-end
- what regressed
- what must be done next

It is deliberately explicit about evidence boundaries:

- local code existence
- local artifact evidence
- real runtime evidence
- real server-side infrastructure evidence

It does **not** treat "code exists" as equivalent to "feature works".

## 1. Baseline Product

`MasterDnsVPN` is a Go DNS-tunnel transport:

- server listens on DNS, typically UDP `53`
- client exposes local SOCKS5, typically `127.0.0.1:18000`
- the original client workflow was config-first and MTU-scan-first
- the project was then modified toward a measurement-first architecture

Primary entrypoints:

- [cmd/client/main.go](/C:/dns/cmd/client/main.go)
- [cmd/server/main.go](/C:/dns/cmd/server/main.go)
- [cmd/scanner/main.go](/C:/dns/cmd/scanner/main.go)

Core configs:

- [client_config.toml](/C:/dns/client_config.toml)
- [client_config.toml.simple](/C:/dns/client_config.toml.simple)
- [server_config.toml.simple](/C:/dns/server_config.toml.simple)

## 2. Development Objective

The development goal evolved in three major phases.

### Phase A: Measurement-first client profiling

Replace "guess config first, then test resolvers" with:

1. neutral probing of candidate resolvers
2. per-resolver profiling
3. derived runtime values from observed resolver behavior
4. warm start from prior registry when valid
5. runtime should use derived values authoritatively

This phase introduced:

- Stage0 / Stage1 / Stage2 probing
- minimal resolver registry
- derived runtime generation
- warm/cold startup model

### Phase B: Runtime adaptation

Add bounded runtime control that:

- reacts to live telemetry over windows
- does not panic on single spikes
- uses stateful control with hysteresis
- can demote/promote and tune targets conservatively

### Phase C: Scanner separation + future multi-instance speed aggregation

Separate resolver discovery/inventory into a local scanner service while preserving the useful probing behavior already achieved in the in-client implementation.

Target architecture:

- scanner owns discovery/inventory/maintenance
- client owns live runtime/session behavior
- eventually client should aggregate throughput across multiple logical instances

Important intended logical instances:

- `1.7a8.ir`
- `0.7x0.ir`
- `2.a5t.ir`

These are intended to be:

- real separate logical instances
- same server process
- separate domains
- separate keys

## 2.1 Unified Target System (Speed-first, Inventory-first, No Gaps)

This is the unified end-product we are building toward. It synthesizes everything learned so far into a single coherent system with clear ownership boundaries and an explicit execution path.

**Primary goal**

Maximize **useful stable throughput** on a given network vantage with this DNS-tunnel protocol, using:

- inventory-first discovery (scanner service)
- measurement-first derived runtime configuration (profiling)
- history-backed runtime adaptation (controller)
- multi-instance capacity (multiple domains+keys) for higher concurrency today, plus mandatory true multi-lane aggregation in the current execution phase
- a single full-lifecycle fixed-layout TUI that shows truth, not scroll logs

### 2.1.1 Non-Negotiable Ownership Boundaries

**Scanner owns (inventory plane):**

- source intake (`scanner_feed.txt`)
- candidate discovery / traversal / CIDR expansion policy
- Stage0/Stage1/Stage2 probing *parity* with the optimized in-client profiler
- inventory maintenance, reserve maintenance, replenish/expand decisions
- per-instance overlay state (domain+key compatibility)

**Client runtime owns (traffic plane):**

- sessions and live traffic transport
- runtime adaptation decisions during real traffic (targets/dup/failover + promote/demote within its current pool)
- high-level demand signaling to scanner (no low-level tuning instructions)

**UI owns nothing.**

- UI is a pure observer of state + events
- no logic should depend on UI being enabled

### 2.1.2 Core Entities and Definitions

**Instance**

One logical instance is exactly:

- `instance_id` (stable id, currently equals domain)
- `domain`
- `encryption_method`
- `raw key` (hex string)
- `key_fingerprint` (derived)

Evidence (current local manifest and keyring):

- [scanner_instances.json](/C:/dns/scanner_instances.json)
- [scanner_keys.json](/C:/dns/scanner_keys.json)
- [client_domain_keyring.json](/C:/dns/client_domain_keyring.json)

**Endpoint**

- canonical resolver endpoint = `ip:port` (port defaults to 53)
- endpoints are not pre-filtered by private/CGNAT (only hard-invalid rejected)

**Inventory model (mandatory two-layer model)**

1. base candidate facts (shared across instances)
2. per-instance overlay facts for `(instance, endpoint)`

Evidence (current store format):

- [scanner_store.json](/C:/dns/scanner_store.json)

**Inventory buckets (per instance)**

- `active_ready`: strongly usable now (profile-complete)
- `reserve_ready`: usable backups (profile-complete)
- `cold_known`: known candidates but not recently validated / not in ready
- `quarantined`: temporary suppression (quality decay / unstable)
- `carrier_blocked_or_incompatible`: REFUSED/SERVFAIL-dominant compatibility failures
- `retired`: instance removed/disabled (stop scanning new work)

### 2.1.3 Unified Full-Lifecycle Control Loops

There are exactly two control loops, with a clear contract between them.

**Loop A: scanner inventory control (long-lived service)**

- maintains per-instance ready pools over time
- reacts to client demand signals (reserve low / unhealthy)
- inventory-first: warm start -> maintenance -> replenish -> expand (world scan only if needed)

**Loop B: per-instance runtime controller (in client)**

- consumes live telemetry (windows: 10s / 60s / 5-10m)
- adjusts operating point (targets/dup/failover) stepwise with hysteresis
- demotes/quarantines resolvers based on sustained evidence
- never treats REFUSED/SERVFAIL as quality decay

**Contract from runtime -> scanner (high-level only)**

Runtime sends "need" signals, never "how":

- `reserve_low`
- `active_pool_degraded`
- `instance_unhealthy`
- `need_more_ready_resolvers`
- optional: `intent = maximize | balanced | low_overhead`

Scanner decides the inventory actions (replenish/expand/refresh).

### 2.1.4 How Multi-Instance Helps Speed (Current Phase Deliverables)

We intentionally separate two complementary implementation tracks that are both mandatory in this phase:

1. **Concurrency scaling (mandatory now):** per-connection routing across instances
2. **Single-flow max speed (mandatory now):** true multi-lane striping + reassembly

**Current-phase track A (mandatory): single-process multi-instance hub**

- one client process hosts N logical instances (3 now, scalable to 4/5/10)
- one SOCKS entrypoint routes each inbound TCP connection to exactly one instance (sticky)
- result: Telegram + Web (multiple connections) do not collapse on one instance
- this track co-exists with multi-lane implementation work in the same iteration

This is the pragmatic path to an operational product while delivering full aggregation capabilities in the same execution phase.

**Current-phase track B (mandatory): multi-lane aggregated data plane**

- aggregate session id + control lane + data lanes
- chunking + global sequence + reassembly + weighted scheduler
- required deliverable in this iteration to maximize single-flow throughput

Deferral of true multi-lane striping + reassembly to any future phase is explicitly prohibited.

### 2.1.4.1 Execution Scope (Current Phase, Mandatory)

The following implementation items are mandatory deliverables for this iteration:

- lane scheduler (weighted/dynamic)
- chunking + global sequence numbering
- per-lane ACK/timeout policy
- reorder buffer + reassembly window
- loss/duplicate handling
- flow-control/backpressure between lanes
- lane health scoring + lane demotion/promotion
- fail-safe fallback to single-lane in critical conditions

### 2.1.4.2 Slipgate-inspired mechanisms to implement now

Any useful mechanism proposed in recent chats that materially improves speed or stability must be implemented in this phase, not moved to backlog.

Tracking format is mandatory for each mechanism:

- **owner:** directly responsible engineer/agent
- **artifact:** concrete output (design doc, code path, metrics file, or test report)
- **acceptance signal:** observable pass condition in runtime evidence

Execution table (must be maintained during implementation):

- **Mechanism: adaptive lane scheduler policy tuning**
  - owner + artifact + acceptance signal
- **Mechanism: robust chunk integrity and reassembly guardrails**
  - owner + artifact + acceptance signal
- **Mechanism: lane health-driven traffic redistribution**
  - owner + artifact + acceptance signal
- **Mechanism: duplicate suppression and loss recovery hardening**
  - owner + artifact + acceptance signal
- **Mechanism: overload backpressure coordination across lanes**
  - owner + artifact + acceptance signal

### 2.1.5 Configuration Philosophy (Minimal Bootstrap, Max Derivation)

**Bootstrap manual (operator-provided):**

- domain list / instance list
- domain-keyring (`client_domain_keyring.json`)
- local listener bindings (SOCKS)
- scanner address and spawn enable

**Derived from profiling / runtime telemetry (authoritative, preferred):**

- upload target
- download target
- active/reserve sizes
- duplication level
- failover thresholds/cooldowns
- per-resolver classification and readiness

**Derived from system:**

- concurrency defaults (bounded) based on CPU and observed network sensitivity

**Fixed protocol defaults:**

- DNS transport is UDP-to-resolver (not TCP) in this codebase
- tunnel framing / packet types / codec
- TCP tunneling/outbound mode is out of scope for this phase
- current-phase focus is exclusively UDP DNS data-plane + multi-lane over the existing protocol

Note: a formal parameter audit against the official legacy `client_config.toml` is still pending (user will provide).

### 2.1.6 Preconditions and Evidence Discipline

Before interpreting any scan or runtime result, verify prerequisites in this order:

1. **domain+key correctness per instance**
   - `scanner_keys.json` and `client_domain_keyring.json` contain raw keys for all instances
2. **server-side authority correctness**
   - Stage0 direct-to-authoritative (server IP:53) passes for each domain (vantage = server-side)
3. **scanner parity**
   - scanner uses the same Stage0/Stage1/Stage2 pipeline and acceptance as the optimized in-client path

If these are not true, scan results are contaminated and must not be treated as "no usable resolvers exist".

### 2.1.7 Target End-to-End Flow (Operational, Full Lifecycle)

This is the intended operational lifecycle when the product is "done enough" for real daily use.

1. scanner service starts (or is spawned locally by the client)
2. scanner loads:
   - desired instance manifest ([scanner_instances.json](/C:/dns/scanner_instances.json))
   - keyring ([scanner_keys.json](/C:/dns/scanner_keys.json))
   - store ([scanner_store.json](/C:/dns/scanner_store.json))
   - resolver feed ([scanner_feed.txt](/C:/dns/scanner_feed.txt))
3. scanner inventory-first loop:
   - warm start for each enabled instance
   - maintenance refresh
   - replenish when needed
   - expand/world scan only if still insufficient
4. client starts (single process)
5. client starts full-lifecycle fixed-layout TUI (only if interactive TTY)
6. client connects to scanner (local-only IPC), waits until ready
7. client registers each logical instance:
   - instance identity (domain + key fingerprint)
   - lease heartbeat
   - soft intent (optional)
8. client requests warm `active_ready` and `reserve_ready` for each instance
9. **incremental readiness gate (critical):**
   - the client must **not** wait for a "full scan completion"
   - as soon as the scanner can supply a **sufficient ready pool** for an instance, that instance runtime must start and become eligible for routing
   - scanning may take hours/days; readiness is **incremental** and must unblock runtime early
10. per-instance runtime initializes (as soon as instance is ready):
   - apply profiling-derived params if present
   - otherwise use conservative bootstrap and immediately consume ready inventory
11. SOCKS entrypoint accepts connections and routes each TCP connection to a chosen instance (sticky)
11. per-instance runtime controller runs continuously:
   - uses rolling windows and derived signals (not instant events)
   - adjusts targets/dup/failover conservatively
   - demote/promote within its ready pool
12. when per-instance health/reserve degrades beyond guardrails, client emits demand signals to scanner
13. scanner replenishes inventory in background; client consumes replacements without crashing existing traffic

### 2.1.8 Runtime <-> Scanner Interaction (When Do We Signal?)

The controller must be able to "hold the line" temporarily by tuning parameters, but must not mask chronic inventory collapse.

The intended rule is:

- runtime adaptation optimizes within the current pool
- scanner replenishment restores the pool when the pool becomes the limiting factor

Signals are triggered only on **sustained** evidence (window-based), and the signal payload is high-level:

- `reserve_low`:
  - sustained `reserve_ready_count` below minimum for that instance
  - or repeated demotions without reserve replacement availability
- `active_pool_degraded`:
  - sustained drop in useful throughput *with* rising timeouts / tail latency pressure
  - not a one-off RTT spike
- `carrier_incompatible_spike`:
  - REFUSED/SERVFAIL rises significantly among the currently used candidates (carrier policy)
  - indicates we likely need different endpoints, not just different targets/dup
- `need_more_ready_resolvers`:
  - active count falls and reserve cannot restore it

### 2.1.8.1 Readiness Thresholds and "Connect ASAP" Policy

This is a first-class requirement:

- **runtime must connect/start as soon as it is possible to do so safely**
- "full scan done" is never a prerequisite for starting runtime

Practically:

- each instance has a configurable readiness threshold (counts), for example:
  - `min_active_ready`
  - `min_reserve_ready`
- the client should:
  - poll or subscribe to scanner inventory updates
  - start/enable the instance as soon as it crosses thresholds
  - keep running even if other instances are still scanning
- the scanner should:
  - return the best currently-known ready pool immediately (warm start)
  - keep scanning/maintenance in the background
  - update ready pools incrementally (do not batch until the whole feed is traversed)

The UI must make this visible:

- per-instance state: `waiting_for_ready` -> `ready` -> `connected`
- scanner state: `scanning` continues even while runtime is already serving traffic

### 2.1.9 Scale Targets (Scanner Must Be Ready for Millions of Endpoints)

The scanner must eventually be able to handle ~5M endpoints without becoming effectively serial or self-sabotaging quality.

This implies:

- **feed traversal fairness**
  - persistent cursor / rotating start so it does not re-check the beginning forever
- **phase-aware bounded concurrency**
  - high concurrency for cheap Stage0-like probing
  - lower concurrency for heavier overlay validation
- **inventory-first priority**
  - maintain existing ready pools before expanding to the world
- **store hygiene**
  - do not persist huge per-endpoint heavy profiles unless needed
  - retain minimal base facts broadly; retain heavier overlay details only for endpoints that become warm/ready candidates

Note: current scanner parity uses full profile intelligence for readiness admission. For 5M-scale operation, the practical model is:

- broad cheap filtering (Stage0-like) across huge universe
- Stage1/Stage2 only on the subset that is being promoted into ready buckets or re-validated for readiness

### 2.1.10 Operator UI Contract (Single Screen, Full Lifecycle, Network-Monitor Style)

When TUI is enabled, the operator must see a single stable screen (no append-only logs) from startup through connected runtime.

Minimum UI truth to display:

- global header:
  - current lifecycle state (profiling / warm start / connecting / connected / degraded / recovering)
  - elapsed time
  - scanner connectivity state
- scanner panel:
  - scanning vs idle
  - feed progress (cursor/position)
  - base candidates count
  - per-instance ready counts (`active_ready`, `reserve_ready`, `cold_known`, `quarantined`, `carrier_blocked`)
- per-instance panels (one row each):
  - domain / key fingerprint short
  - current derived runtime knobs (upload target, download target, duplication, failover)
  - real throughput (wire tx/rx and useful tx/rx) and efficiency ratios
  - current health indicator (green->red) based on sustained windowed signals
  - resolver spectrum view (strongest -> weakest; active vs reserve markers)
- bounded event pane:
  - shows important transitions and controller actions without scrolling the whole terminal

The UI must remain an observer: it renders state and recent events; it must not own logic or write directly to network behavior.

## 3. What Was Implemented

## 3.1 AutoProfile Phase 1

### Implemented components

- Stage0 ultra-light viability probing
- Stage1 coarse directional profiling
- Stage2 refinement
- registry persistence
- derived runtime persistence
- warm/cold startup flow
- profiling summary persistence

Primary files:

- [internal/client/auto_profile.go](/C:/dns/internal/client/auto_profile.go)
- [internal/client/auto_profile_stage0.go](/C:/dns/internal/client/auto_profile_stage0.go)
- [internal/client/auto_profile_stage1.go](/C:/dns/internal/client/auto_profile_stage1.go)
- [internal/client/auto_profile_stats.go](/C:/dns/internal/client/auto_profile_stats.go)
- [internal/client/auto_profile_persist.go](/C:/dns/internal/client/auto_profile_persist.go)
- [internal/client/stage0_prober.go](/C:/dns/internal/client/stage0_prober.go)
- [internal/profiling/](/C:/dns/internal/profiling)

### Warm/cold startup model

Warm start:

- reads [resolver_registry.json](/C:/dns/resolver_registry.json)
- filters fresh viable resolvers
- derives runtime immediately if sufficient

Cold start:

- profiles the current resolver input universe
- persists results
- derives runtime and applies it

Key evidence path:

- `resolver_registry.json` (present): [resolver_registry.json](/C:/dns/resolver_registry.json)
- `derived_runtime.json` (generated by profiling runs; removed during artifact cleanup)
- `autoprofile_summary_*.json` (generated by profiling runs; removed during artifact cleanup)

### Verified evidence

Phase 1 "product evidence" artifacts are not present in this checkout because prior run outputs were removed during artifact cleanup.

Historical benchmark (previously observed, artifact removed):

- `total_input_unique = 10276`
- `stage0_viable = 87`
- `final_profile_complete = 54`
- `active = 6`
- `reserve = 48`
- derived runtime: upload target `64`, download target `290`, duplication `4`, failover threshold `5`, failover cooldown `10s`

### Important constraint

The current main runtime config no longer activates this path by default:

- [client_config.toml](/C:/dns/client_config.toml) has `AUTO_PROFILE_RESOLVERS = false`
- scanner-first inventory mode is now enabled there

So the AutoProfile pipeline exists and has been proven in earlier runs, but it is not the active mainline path in the current default config.

## 3.2 Runtime Adaptation

### Implemented components

The runtime controller exists and includes:

- state estimator
- runtime state machine
- bounded control loop
- telemetry-window aggregation
- demote/promote hooks
- target adjustment hooks
- duplication adjustment hooks
- failover adjustment hooks
- reserve probing hooks

Primary file:

- [internal/client/runtime_adaptation.go](/C:/dns/internal/client/runtime_adaptation.go)

State machine values:

- `STABLE`
- `CAUTIOUS`
- `DEGRADED`
- `RECOVERING`

Telemetry and persistence artifacts:

Telemetry persistence exists in code (live + end-of-run summary), but previously generated files were removed during artifact cleanup:

- `telemetry_live.json` (generated; removed)
- `telemetry_summary_*.json` (generated; removed)

### Verified evidence

This checkout does not currently include runtime evidence artifacts (telemetry/log summaries) because they were removed during artifact cleanup.

Historical note (artifact removed):

- demotion behavior was observed during a real traffic run

### Current maturity

Runtime adaptation is **implemented**, but not all branches are equally proven in natural runtime evidence.

What is evidenced:

- controller activation
- state reporting
- demote behavior

What is less strongly evidenced:

- promote under real load
- duplication change under useful traffic
- failover tuning under meaningful multi-lane behavior
- target before/after validation in a production-quality scenario

Also note:

- the controller is intended to own dynamic runtime decisions
- legacy health-loop code still exists, but scanner mode suppresses the main inactive-pool scanner-style recheck path

Relevant files:

- [internal/client/client.go](/C:/dns/internal/client/client.go)
- [internal/client/mtu.go](/C:/dns/internal/client/mtu.go)

### Telemetry Semantics (Wire vs Useful)

These definitions are important because the product goal is **useful stable throughput**, not just "bytes on the wire".

**Wire counters (UDP transport cost)**

- `wire_bytes_tx`: bytes written to the UDP socket toward resolver endpoints (includes protocol overhead, duplication overhead, and retransmits).
- `wire_bytes_rx`: bytes read from the UDP socket from resolver endpoints.

**Useful counters (tunnel payload progress)**

- `useful_ingress_tx`: bytes accepted by the client tunnel layer from upper layers for sending (input demand).
- `useful_acked_tx`: bytes confirmed as successfully transmitted end-to-end (acknowledged progress). If full ack semantics are not available for every byte, the current implementation uses the best available "delivered/confirmed" proxy.
- `useful_delivered_rx`: bytes successfully decoded and delivered to the upper stream on receive.

**Efficiency**

- `tx_efficiency = useful_acked_tx / wire_bytes_tx`
- `rx_efficiency = useful_delivered_rx / wire_bytes_rx`

These are the primary "is the system wasting wire bandwidth" signals for adaptation and for operator UI.

**Outcome mix (per resolver / per instance)**

For each resolver used in runtime (and for scanner probing), outcomes must remain separated:

- `ok`
- `timeout`
- `refused` (carrier/policy incompatibility)
- `servfail` (carrier/policy incompatibility)
- `malformed` / `extract_failed` (protocol shape mismatch)
- `other`

**RTT**

- `rtt_p50`, `rtt_p90` are computed only on successful tunnel responses (`ok`) and are used as health signals (tail inflation).

**Decision style (relative, not absolute)**

The runtime controller and scanner classification are intended to avoid brittle absolute thresholds. Instead they use:

- quantiles within the active window (e.g., bottom quartile = weak)
- relative-to-rolling-best baselines (e.g., RTT inflation vs recent best)
- before/after delta validation for target/dup changes when possible

## 3.3 Full-Lifecycle TUI

### Implemented components

A fixed-layout full-lifecycle terminal dashboard was added using `tview`.

Primary files:

- [internal/client/full_tui.go](/C:/dns/internal/client/full_tui.go)
- [internal/client/full_tui_events.go](/C:/dns/internal/client/full_tui_events.go)
- [internal/client/auto_profile_tui.go](/C:/dns/internal/client/auto_profile_tui.go)

Design intent:

- single render owner
- no raw terminal append spam when TUI is active
- bounded event pane
- profiling and runtime state in one lifecycle view

Displayed concepts in code:

- phase/state
- derived runtime knobs
- session state
- throughput
- resolver counts
- runtime events

### Evidence boundary

The TUI code exists and is structured correctly, but this handoff does not claim a fresh verified interactive run from the current exact repo state.

So status is:

- implemented in code
- partially evidenced by prior run artifacts
- not fully re-proven from the current snapshot

## 3.4 Scanner Service

### Intended architecture

The scanner was split into a separate local process/service.

Primary scanner files:

- [cmd/scanner/main.go](/C:/dns/cmd/scanner/main.go)
- [internal/scanner/config.go](/C:/dns/internal/scanner/config.go)
- [internal/scanner/feed.go](/C:/dns/internal/scanner/feed.go)
- [internal/scanner/http_api.go](/C:/dns/internal/scanner/http_api.go)
- [internal/scanner/manifest.go](/C:/dns/internal/scanner/manifest.go)
- [internal/scanner/keyring.go](/C:/dns/internal/scanner/keyring.go)
- [internal/scanner/service.go](/C:/dns/internal/scanner/service.go)
- [internal/scanner/store_io.go](/C:/dns/internal/scanner/store_io.go)
- [internal/scanner/types.go](/C:/dns/internal/scanner/types.go)

### API surface

Implemented local HTTP API:

- `/health`
- `/v1/instances/register`
- `/v1/instances/heartbeat`
- `/v1/instances/demand`
- `/v1/instances/list`
- `/v1/instances/{id}/warm`
- `/v1/instances/{id}/summary`
- `/v1/instances/{id}/replenish`

### Store and feed artifacts

Key files:

- [scanner_store.json](/C:/dns/scanner_store.json)
- [scanner_instances.json](/C:/dns/scanner_instances.json)
- [scanner_keys.json](/C:/dns/scanner_keys.json)
- [scanner_feed.txt](/C:/dns/scanner_feed.txt)

Feed parser supports:

- `IP`
- `IP:port`
- CIDR input via the shared resolver loader
- duplicate suppression
- invalid-line accounting

### Scanner concurrency and traversal

Scanner was modified to avoid being effectively serial:

- explicit per-phase concurrency knobs were added
- feed traversal was changed to use per-instance persisted cursor progress
- store snapshot save was hardened to avoid concurrent map serialization crashes

Evidence in code:

- [internal/scanner/config.go](/C:/dns/internal/scanner/config.go)
- [internal/scanner/service.go](/C:/dns/internal/scanner/service.go)
- [internal/scanner/store_io.go](/C:/dns/internal/scanner/store_io.go)
- [cmd/scanner/main.go](/C:/dns/cmd/scanner/main.go)

### Scanner probing parity (important)

Scanner endpoint validation is intended to match the optimized in-client profiling behavior, not to be a weaker Stage0-only probe.

Current parity implementation:

- scanner uses `InventoryProber`, which reuses `profileOneResolver` (Stage0/Stage1/Stage2) for per-endpoint validation
- "ready" admission requires profile-complete results (upload+download recommended bytes > 0)
- scanner stores profile summary fields per `(instance, endpoint)` overlay (recommended/max bytes)

Evidence in code:

- [internal/client/inventory_prober.go](/C:/dns/internal/client/inventory_prober.go)
- [internal/scanner/service.go](/C:/dns/internal/scanner/service.go)
- [internal/scanner/types.go](/C:/dns/internal/scanner/types.go)

### Scanner/client coordination

Client-side coordination files:

- [internal/client/scanner_coord.go](/C:/dns/internal/client/scanner_coord.go)

Implemented coordination:

- scanner health check
- optional local spawn
- instance registration
- heartbeat loop
- demand loop
- warm-start candidate request
- applying scanner-provided active/reserve connections into the balancer

## 3.5 Multi-domain + Multi-key Support

### Client-side

Per-domain keyring support exists on the client.

Files:

- [internal/client/domain_keyring.go](/C:/dns/internal/client/domain_keyring.go)
- [internal/client/async_runtime.go](/C:/dns/internal/client/async_runtime.go)
- [internal/client/tunnel_query.go](/C:/dns/internal/client/tunnel_query.go)
- [internal/config/client.go](/C:/dns/internal/config/client.go)

Key local artifact:

- [client_domain_keyring.json](/C:/dns/client_domain_keyring.json)

This currently contains:

- `1.7a8.ir`
- `0.7x0.ir`
- `2.a5t.ir`

with separate raw keys.

### Server-side

Per-domain key routing exists on the server.

Files:

- [internal/udpserver/codec_router.go](/C:/dns/internal/udpserver/codec_router.go)
- [internal/udpserver/server_ingress.go](/C:/dns/internal/udpserver/server_ingress.go)
- [internal/config/server.go](/C:/dns/internal/config/server.go)

Remote deployment state:

- server root: `/opt/masterdnsvpn/1.7a8.ir`
- config: `/opt/masterdnsvpn/1.7a8.ir/server_config.toml`
- domain keyring: `/opt/masterdnsvpn/1.7a8.ir/domain_keyring.json`
- service: `masterdnsvpn-1.7a8.ir.service`

Current remote config evidence shows:

- `DOMAIN = ["1.7a8.ir", "0.7x0.ir", "2.a5t.ir"]`
- `DOMAIN_KEYRING_FILE = "domain_keyring.json"`

Key files on server:

- `/opt/masterdnsvpn/1.7a8.ir/encrypt_key.txt`
- `/opt/masterdnsvpn/1.7a8.ir/keyring/key_0.7x0.ir.txt`
- `/opt/masterdnsvpn/1.7a8.ir/keyring/key_2.a5t.ir.txt`

Known keys currently wired:

- `1.7a8.ir` -> `bccff1164f48bbafcb811db1dd4f39a0`
- `0.7x0.ir` -> `17f319991362b7deef755d893ded6118`
- `2.a5t.ir` -> `f5970cd92e14824212ce7e2eb23e6b51`

### Server runtime evidence

Observed remote status:

- `masterdnsvpn-1.7a8.ir.service` is enabled and active
- server is bound on UDP `:53`

Observed additional remote residue:

- another process `RoboCop-v1-serv` is listening on `:5301`
- no current evidence in this handoff that `:5302` or `:5303` are active

This indicates the active deployment model is:

- one main `masterdnsvpn` process on `:53`
- old residue may still exist on side ports

## 4. What Was Verified vs What Only Exists

This section is intentionally blunt.

### Verified

- AutoProfile Phase 1 exists and produced strong real results on `1.7a8.ir`
- warm-start derived runtime was applied and used in real sessions
- SOCKS client successfully carried real TCP CONNECT traffic in the earlier single-domain path
- runtime adaptation controller runs and demote events were observed
- multi-domain multi-key server config exists and is active on real infrastructure
- scanner exists as a separate binary/service model

### Exists but not fully verified end-to-end

- full-lifecycle TUI in the current exact snapshot
- scanner steady-state behavior as a robust long-lived service
- scanner/client lifecycle resilience from the current exact snapshot
- full runtime adaptation path coverage under production-like load

### Mandatory in current iteration (implementation required now)

- true multi-instance aggregated speed data plane
- aggregate session identity across instance lanes
- control lane + data lanes model
- aggregate chunking
- global sequence space for striped aggregate traffic
- multi-lane receiver-side reassembly
- lane replacement and retransmit model for aggregated data plane
- weighted cross-instance data striping scheduler

## 5. Scanner Parity Audit

Scanner separation is intended to change only the process boundary and feed/service contract, not scanning intelligence.

### Intended meaning of "scanner separation"

- preserve the improved scanning/profiling intelligence
- change only process boundary and feed/service contract
- do not create a weaker or different scanning product

### Before separation (optimized in-client profiling)

The optimized in-client profiling path used:

- Stage0 viability
- Stage1 directional coarse profiling
- Stage2 refinement
- per-resolver profiling persistence
- derived runtime generation from measured results

Evidence (code):

- [internal/client/auto_profile.go](/C:/dns/internal/client/auto_profile.go)
- [internal/client/auto_profile_stage0.go](/C:/dns/internal/client/auto_profile_stage0.go)
- [internal/client/auto_profile_stage1.go](/C:/dns/internal/client/auto_profile_stage1.go)

Historical benchmark (artifact removed during cleanup):

- `stage0_viable = 87`
- `profile_complete = 54`

### After separation (scanner service, current code)

Scanner endpoint validation now reuses the same optimized profiling intelligence via `InventoryProber`:

- Stage0 viability
- Stage1 directional coarse profiling
- Stage2 refinement (recommended-point validation)
- "ready" admission requires profile-complete results (not Stage0-only)

Evidence (code):

- [internal/client/inventory_prober.go](/C:/dns/internal/client/inventory_prober.go)
- [internal/scanner/service.go](/C:/dns/internal/scanner/service.go)
- [internal/scanner/types.go](/C:/dns/internal/scanner/types.go)

### Practical outcome caveat (store staleness)

The persisted [scanner_store.json](/C:/dns/scanner_store.json) may reflect older runs. Treat it as stale until a fresh scan is run with the parity-fixed scanner.

### Parity verdict

- code parity: implemented
- parity proof: not present in current artifacts (requires a fresh scanner run)

## 6. Current Mainline Runtime Flow

The current mainline runtime behavior is defined by:

- [client_config.toml](/C:/dns/client_config.toml)
- [internal/client/client.go](/C:/dns/internal/client/client.go)
- [internal/client/scanner_coord.go](/C:/dns/internal/client/scanner_coord.go)
- [internal/config/client.go](/C:/dns/internal/config/client.go)

### Effective flow now

1. client starts
2. TUI may start if terminal is interactive
3. scanner coordination starts
4. scanner may be spawned locally
5. client writes `scanner_instances.json` and `scanner_keys.json`
6. client registers instances with scanner
7. client requests warm candidates from scanner
8. because `AUTO_PROFILE_RESOLVERS = false`, full AutoProfile is skipped
9. because `SCANNER_ENABLED = true`, client applies conservative bootstrap MTU from config
10. runtime controller starts
11. if no active scanner lanes exist, client waits in scanner-wait loop
12. if at least one active lane exists, session init proceeds

This means the active mainline path is **scanner-first**, not **profile-first**.

## 7. Current Config and Artifact State

## 7.1 Main client config

Current main config:

- [client_config.toml](/C:/dns/client_config.toml)

Important current values:

- `DOMAINS = ["1.7a8.ir", "0.7x0.ir", "2.a5t.ir"]`
- `DOMAIN_KEYRING_FILE = "client_domain_keyring.json"`
- `SCANNER_ENABLED = true`
- `SCANNER_SPAWN = true`
- `AUTO_PROFILE_RESOLVERS = false`

Meaning:

- runtime is configured to depend on scanner inventory
- old optimized in-client profiling path is not the active default path

## 7.2 Current local scanner artifacts

- [scanner_instances.json](/C:/dns/scanner_instances.json)
- [scanner_keys.json](/C:/dns/scanner_keys.json)
- [scanner_store.json](/C:/dns/scanner_store.json)
- [scanner_feed.txt](/C:/dns/scanner_feed.txt)

Scanner manifest currently represents the three logical instances separately:

- instance_id = `1.7a8.ir`
- instance_id = `0.7x0.ir`
- instance_id = `2.a5t.ir`

Scanner keys file currently contains raw keys for all three.

## 7.3 Evidence of earlier successful single-domain runtime

Earlier single-domain runtime success was verified during development, but the concrete log artifact was removed during artifact cleanup.

Historical note (artifact removed):

- warm-start derived runtime applied
- session initialization succeeded
- SOCKS listening
- actual CONNECT traffic
- runtime adaptation demote actions observed

This is single-domain-oriented evidence, not multi-instance evidence.

## 8. What Is Missing To Reach the Intended Final Goal

Current-iteration product target (mandatory):

- one client process hosts 3 logical instances (domain+key isolated)
- scanner supplies per-instance warm/ready inventory and replenishes on demand
- client routes each inbound SOCKS TCP stream to exactly one chosen instance (HAProxy-style routing) while multi-lane striping/reassembly is implemented in parallel in the same iteration
- runtime adaptation keeps each instance near its best stable operating point
- one unified console UI shows per-instance throughput/health and scanner state

Same-iteration mandatory target:

- true multi-lane aggregated transport (striping + reassembly across instances) as part of this iteration's deliverables

### Missing technical blocks (as of this checkout)

1. scanner parity proof (post-fix)

- code parity is implemented (scanner uses optimized profiling per endpoint)
- a fresh scanner run is still required to prove it produces robust ready pools for all 3 instances

2. multi-instance single-process client core

- 3 logical instance runtimes inside one process
- one SOCKS entrypoint that routes per connection (sticky), not per packet
- per-instance demand signaling to scanner when reserve/health is insufficient

3. operational UI proof

- prove a live run where the unified UI shows real traffic, real per-instance throughput, and real scanner inventory behavior

## 9. Recommended Next Work Order

This section is intentionally operational and time-boxed.

Iteration 1 (foundation): scanner parity + 3-instance inventory

- run scanner with parity-fixed probing and confirm non-trivial `active_ready`/`reserve_ready` for all:
  - `1.7a8.ir`
  - `0.7x0.ir`
  - `2.a5t.ir`
- confirm "ready" means profile-complete (not Stage0-only)
- confirm client consumes scanner inventory and only sends high-level demand signals
- ensure scanner traversal makes progress across feed (cursor/rotation) and uses phase-aware bounded concurrency

Iteration 2 (product core): single-process 3-instance client + HAProxy-style routing

- implement a single SOCKS listener that routes each TCP stream to one selected instance runtime
- keep stickiness per connection; avoid per-request thrash
- expose per-instance telemetry (wire/useful throughput, active/reserve, health) for UI
- ensure design is scalable to N instances (not hard-coded to 3)

Iteration 3 (operability): unified UI + proof run

- unify console UI into a network-monitor style dashboard:
  - 3 instances, one screen
  - real per-instance tx/rx throughput and efficiency
  - resolver counts and health (green->red spectrum)
  - scanner status (idle/scanning) + inventory counts per instance
  - derived runtime knobs per instance
- run a bounded real-traffic proof session and capture the regenerated evidence artifacts, including multi-lane striping/reassembly evidence

## 10. Practical Risks and Landmines

These are the main continuation risks a future engineer/agent must respect.

### Risk 1: Confusing “code exists” with “feature works”

The repository contains substantial code for scanner, TUI, and runtime adaptation.

Do not assume:

- TUI = fully verified UX
- adaptation code = fully proven control behavior
- scanner separation = parity achieved
- multi-domain keys = aggregate speed feature finished

### Risk 2: Misreading scanner success

The scanner store may show some ready inventory for `1.7a8.ir`.

That does **not** prove:

- parity with the old optimized client profiling path
- readiness of `0.7x0.ir`
- readiness of `2.a5t.ir`
- aggregate multi-instance viability

### Risk 3: Mixing server-side prerequisites with final product goal

The server already supports:

- three domains
- three keys
- one process

That is only prerequisite infrastructure, not the multi-instance speed feature itself.

### Risk 4: Old runtime artifacts can be misleading

Prior run artifacts (logs, telemetry summaries, profiling summaries) were intentionally removed during artifact cleanup. Continuation work must regenerate fresh evidence from the current code/config rather than relying on stale files.

## 11. File Index for Continuation

### Client runtime and profiling

- [internal/client/client.go](/C:/dns/internal/client/client.go)
- [internal/client/async_runtime.go](/C:/dns/internal/client/async_runtime.go)
- [internal/client/mtu.go](/C:/dns/internal/client/mtu.go)
- [internal/client/auto_profile.go](/C:/dns/internal/client/auto_profile.go)
- [internal/client/auto_profile_stage0.go](/C:/dns/internal/client/auto_profile_stage0.go)
- [internal/client/auto_profile_stage1.go](/C:/dns/internal/client/auto_profile_stage1.go)
- [internal/client/auto_profile_stats.go](/C:/dns/internal/client/auto_profile_stats.go)
- [internal/client/auto_profile_persist.go](/C:/dns/internal/client/auto_profile_persist.go)
- [internal/client/inventory_prober.go](/C:/dns/internal/client/inventory_prober.go)
- [internal/client/runtime_adaptation.go](/C:/dns/internal/client/runtime_adaptation.go)
- [internal/client/stage0_prober.go](/C:/dns/internal/client/stage0_prober.go)
- [internal/client/telemetry_persist.go](/C:/dns/internal/client/telemetry_persist.go)

### Scanner

- [cmd/scanner/main.go](/C:/dns/cmd/scanner/main.go)
- [internal/scanner/service.go](/C:/dns/internal/scanner/service.go)
- [internal/scanner/http_api.go](/C:/dns/internal/scanner/http_api.go)
- [internal/scanner/feed.go](/C:/dns/internal/scanner/feed.go)
- [internal/scanner/store_io.go](/C:/dns/internal/scanner/store_io.go)
- [internal/scanner/types.go](/C:/dns/internal/scanner/types.go)

### Client/scanner boundary

- [internal/client/scanner_coord.go](/C:/dns/internal/client/scanner_coord.go)
- [internal/config/client.go](/C:/dns/internal/config/client.go)

### Domain keyring support

- [internal/client/domain_keyring.go](/C:/dns/internal/client/domain_keyring.go)
- [internal/udpserver/codec_router.go](/C:/dns/internal/udpserver/codec_router.go)
- [internal/config/server.go](/C:/dns/internal/config/server.go)

### UI

- [internal/client/full_tui.go](/C:/dns/internal/client/full_tui.go)
- [internal/client/full_tui_events.go](/C:/dns/internal/client/full_tui_events.go)
- [internal/client/auto_profile_tui.go](/C:/dns/internal/client/auto_profile_tui.go)

### High-value artifacts

- [resolver_registry.json](/C:/dns/resolver_registry.json)
- [scanner_store.json](/C:/dns/scanner_store.json)
- [scanner_instances.json](/C:/dns/scanner_instances.json)
- [scanner_keys.json](/C:/dns/scanner_keys.json)
- [scanner_feed.txt](/C:/dns/scanner_feed.txt)
- [client_domain_keyring.json](/C:/dns/client_domain_keyring.json)

Generated artifacts that are expected in real runs but are not present after cleanup:

- `autoprofile_summary_*.json`
- `derived_runtime.json`
- `telemetry_live.json`
- `telemetry_summary_*.json`
- runtime log captures

## 12. Final Status Summary

The repository is in a **partially advanced but not yet end-goal-complete** state.

In short:

- Phase 1 profiling is implemented (historically proven; artifacts removed)
- runtime adaptation is implemented (requires fresh proof artifacts)
- scanner separation was implemented architecturally
- multi-domain/multi-key serving was implemented on server and client
- scanner parity was previously broken; parity logic is now restored in code via `InventoryProber` (still needs fresh proof run)
- true multi-lane aggregated speed transport is a mandatory deliverable in the current execution phase and must be implemented now

Any continuation effort should treat these as the primary continuation boundary:

1. prove scanner parity + 3-instance ready pools
2. ship single-process 3-instance client + HAProxy-style per-connection routing + unified UI
3. implement and validate multi-lane striping/reassembly within this same execution phase; do not postpone

## 13. Immediate Acceptance Criteria (Current Iteration)

The current iteration is accepted only when all criteria below are met with concrete artifacts.

### 13.1 Single-flow throughput success criteria

- single-flow throughput with multi-lane striping enabled must exceed single-lane baseline by an agreed measurable margin in repeated runs
- throughput gain must be reported for both median and sustained window measurements (not one-shot peak)
- evidence artifact: `striping_metrics_*.json`

### 13.2 Stability criteria (tail latency, loss tolerance, reorder tolerance)

- tail latency (`p95`/`p99`) must stay inside defined operational bounds under normal loss/reorder conditions
- controlled packet loss injection must show graceful degradation without session collapse
- reorder tolerance must be demonstrated by successful reassembly integrity under out-of-order delivery pressure
- evidence artifacts:
  - `striping_metrics_*.json`
  - `reassembly_integrity_*.json`

### 13.3 Degrade-safe behavior criteria

- lane health degradation must trigger deterministic demotion/promotion behavior
- critical instability must trigger fail-safe fallback to single-lane mode without hard traffic break
- recovery from fail-safe fallback must preserve correctness and return to multi-lane only when health criteria are satisfied
- evidence artifact: `lane_health_summary_*.json`

### 13.4 Required evidence package (artifact names)

- `striping_metrics_*.json`
- `reassembly_integrity_*.json`
- `lane_health_summary_*.json`

Absence of this evidence package means the iteration is not accepted.
