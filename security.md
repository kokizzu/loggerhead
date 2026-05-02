# Security Risk Assessment

This document reviews security risks in Loggerhead based on the current codebase.

## Scope and method

I reviewed:

- Network-facing TCP query listeners (`SAVE`, `DELETE`, `GET`, `POLY`)
- Cluster gossip/broadcast/state sync behavior
- Admin HTTP endpoints and frontend rendering
- Memory/CPU abuse paths (including cost-amplification / financial-DoS scenarios)
- Language/runtime-specific risk posture for Go and HTML/JS

---

## 1) OWASP Top 10 mapping (application-focused)

### A01: Broken Access Control

**Risk:** High

- All data-plane operations are unauthenticated over TCP (`SAVE`, `DELETE`, `GET`, `POLY`). Any network-reachable client can read/write/delete data.
- Admin endpoints (`/`, `/admin-data`, `/metrics`) are also unauthenticated.

**Abuse:** Unauthorized data deletion, tampering, and observability leakage.

**Evidence:**
- `server/listener.go`: executes every line as a query without auth checks.
- `admin/ops.go`: registers admin and metrics routes with no auth middleware.

**Mitigations:**
- Add mTLS or at least token/HMAC auth for data-plane commands.
- Restrict bind interfaces and enforce network policies.
- Put admin/metrics behind auth and IP allowlists.

### A02: Cryptographic Failures

**Risk:** High

- Traffic is plain TCP/HTTP. No transport encryption for client queries, cluster gossip, or admin API.

**Abuse:** Sniffing, replay, in-path command manipulation.

**Mitigations:**
- mTLS for client ports and cluster communication.
- TLS termination + strict internal segmentation for admin/metrics.

### A03: Injection

**Risk:** Medium

- Protocol parser is simple string splitting (space-delimited) with no escaping/quoting model.
- While this is not SQL injection, malformed commands and unbounded identifiers can be used to trigger expensive processing and state growth.

**Mitigations:**
- Define strict grammar and max field lengths.
- Reject oversized namespaces/IDs early.

### A04: Insecure Design

**Risk:** High

- Read paths auto-create namespaces (`GET`/`POLY` against random namespace creates state).
- Cluster trust model implicitly trusts any joined node and applies remote commands/state.

**Abuse:** Low-cost memory amplification and cluster poisoning.

**Mitigations:**
- Make reads side-effect free (do not create namespace on read).
- Require authenticated node identity before accepting cluster state/commands.

### A05: Security Misconfiguration

**Risk:** High

- Defaults expose multiple open ports and admin/metrics endpoints.
- No security headers, auth middleware, or hardened transport defaults.

**Mitigations:**
- Secure-by-default config profile (localhost bind for admin; auth required).
- Deployment hardening guide (network policies, firewalls, mTLS).

### A06: Vulnerable and Outdated Components

**Risk:** Medium

- Project vendors dependencies, including cluster/network libraries; if not regularly updated, known CVEs may persist.
- Frontend includes bundled JS/CSS; dependency hygiene relies on manual refresh.

**Mitigations:**
- Add automated dependency scanning (govulncheck, osv-scanner, Dependabot/Renovate).
- Pin + routinely refresh vendored dependencies.

### A07: Identification and Authentication Failures

**Risk:** High

- No user/service authentication model for critical operations.

**Mitigations:**
- API auth layer (service tokens, mTLS cert identities, or signed requests).

### A08: Software and Data Integrity Failures

**Risk:** High

- Cluster node messages are accepted and executed without signed integrity checks.
- Remote state merge trusts incoming serialized state.

**Mitigations:**
- Authenticate cluster peers; sign/verify broadcast payloads.
- Validate and bound remote state before merge.

### A09: Security Logging and Monitoring Failures

**Risk:** Medium

- Logs exist for connection errors/events, but there is limited structured security telemetry:
  - no audit trail of caller identity
  - no anomaly/rate-limit detection
  - limited abuse signaling

**Mitigations:**
- Structured audit logs (source IP, command type, outcome, latency).
- Alerts for abnormal write/delete/query and connection patterns.

### A10: SSRF

**Risk:** Medium

- `/admin-data` fans out server-side HTTP requests to every cluster member.
- While targets come from membership, compromised membership can force internal request fanout behavior.

**Mitigations:**
- Require auth for `/admin-data`.
- Add request budget/rate limits and target validation.

---

## 2) “Complex memory safety” class issues (use-after-free, stack overflow, etc.)

## Use-after-free / heap corruption

- **Go significantly reduces classic UAF/dangling-pointer memory corruption** compared with C/C++.
- No obvious unsafe-pointer usage in core paths reviewed.

**Residual concern:** application-level race conditions and logic corruption remain possible even without native-memory UAF.

## Stack overflow / recursion exhaustion

**Risk:** Low-to-Medium (theoretical abuse path)

- QuadTree recursion (`QueryRange`, insertion path) can deepen with pathological distributions; repeated subdivision can increase recursion depth.
- Go stacks grow dynamically, but extreme recursion can still panic.

**Mitigations:**
- Add max tree depth safeguards.
- Consider iterative traversal for range queries.

## Panic-driven denial of service

**Risk:** Medium

- Several paths panic on unexpected conditions (e.g., decode/merge assumptions). In a networked distributed system, malformed or hostile state can trigger crash loops.

**Mitigations:**
- Replace panics on remote/input-driven paths with explicit errors.
- Quarantine/reject malformed remote state rather than crashing.

---

## 3) Known risk areas specific to Go and HTML/JS in this codebase

## Go-specific concerns

1. **Slowloris-style connection exhaustion** (High)
   - Connections can stay open waiting for line completion; attacker can hold connection slots with slow input.
   - `MaxConnections` limits concurrency but still allows cheap slot starvation.
   - Add per-connection read deadlines and idle timeouts.

2. **Memory amplification through namespace/id cardinality** (High)
   - Arbitrary namespace/id strings can force unbounded map growth.
   - Reads can create namespaces as side effects.
   - Enforce quotas, TTL/eviction, max key lengths, and read-without-create behavior.

3. **Unbounded result generation on wide `POLY`** (Medium)
   - Large area queries can return very large responses, increasing CPU/network load.
   - Add max rows/bytes per response and pagination/stream limits.

## HTML/JS-specific concerns

1. **DOM XSS risk in admin table rendering** (Medium)
   - `admin.js` injects values into HTML template strings and appends to DOM.
   - If node names/addresses are attacker-influenced, this is script-injection-prone.
   - Use text node assignment (`textContent`) or sanitize before insertion.

2. **Admin API data exposure** (High)
   - `/admin-data` exposes runtime/memory/topology details with no auth.
   - Useful for reconnaissance and capacity-targeting.

---

## 4) Business logic abuse risks

1. **Unauthorized delete/tamper** (High)
   - No auth means anyone with network path can mutate state.

2. **Cluster poisoning / malicious node join** (High)
   - Unauthenticated membership allows rogue node behavior:
     - Inject write/delete broadcasts
     - Influence perceived health/topology
     - Participate in state exchange

3. **Consistency abuse** (Medium)
   - Best-effort synchronization can be gamed with churn/flooding to create divergent views and stale reads.

4. **Read side effects violating principle of least surprise** (Medium)
   - `GET`/`POLY` for unknown namespaces creates persistent namespace objects, enabling “read-only” attackers to consume memory.

---

## 5) Financial-DoS (cost amplification) risks

These are attacks that maximize your infrastructure spend per attacker effort.

1. **Namespace cardinality explosion** (High)
   - Send many random namespace IDs via reads/writes to force allocations and long-term memory growth.

2. **High-frequency wide `POLY` scans** (High)
   - Expensive CPU + large response bodies increase compute and bandwidth costs.

3. **Admin fanout amplification** (Medium/High)
   - Repeated `/admin-data` calls cause per-request fanout to all members, multiplying internal traffic and CPU.

4. **Metric scraping abuse** (Medium)
   - Aggressive `/metrics` scraping can materially increase CPU in small nodes.

5. **Potential downstream LLM/token spend amplification** (Contextual)
   - If responses are proxied into an LLM workflow, attacker can generate large responses (many records, frequent queries) that inflate token usage.

**Mitigations (priority):**
- Global and per-IP rate limits.
- Strict quotas on namespaces, IDs, query area, and response bytes.
- AuthN/AuthZ before expensive operations.
- Billing guardrails and anomaly detection.

---

## 6) DDoS and availability risks

1. **Connection slot starvation (Slowloris)** — High
2. **Large fanout/admin poll storms** — Medium/High
3. **Expensive query floods (`POLY`)** — High
4. **Cluster gossip abuse/churn** — High
5. **Crash-oriented malformed state/inputs** — Medium

**Mitigations:**
- Connection/read/write deadlines.
- Token bucket limits (global + per source + per endpoint).
- Query cost controls (complexity budgeting).
- Circuit breakers and backpressure.
- Harden cluster transport and membership auth.

---

## 7) Additional findings (“own stuff”)

1. **Admin server ignores configured HTTP port** (Medium operational/security)
   - Admin server binds hardcoded `:20000` rather than using config, increasing misconfiguration risk and accidental exposure.

2. **No graceful auth boundary between read and write planes** (Medium)
   - Read and write ports are separated, but neither is authenticated; separation alone is not a security boundary.

3. **Potential goroutine pressure in broadcast path** (Medium)
   - Every write defers a send to an unbuffered channel for cluster broadcasting; under pressure, this can increase latency and goroutine blocking behavior.

4. **Insufficient input size bounds** (High)
   - No explicit max length for command lines, IDs, namespaces, or response output; enables memory/cost abuse.

---

## Priority remediation plan

## Immediate (P0)

1. Require authentication + authorization for write operations and admin endpoints.
2. Add transport security (mTLS/internal TLS) for client, admin, and cluster traffic.
3. Stop creating namespaces on read operations.
4. Enforce strict limits: max namespace/id length, max response size, max query area/cardinality.
5. Add per-connection deadlines and per-source rate limiting.

## Near-term (P1)

1. Authenticate cluster membership and sign/validate broadcast messages.
2. Replace panic-on-input/remote-data paths with safe error handling.
3. Harden admin UI rendering against XSS by avoiding raw HTML interpolation.
4. Add dependency/vulnerability scanning to CI.

## Medium-term (P2)

1. Add query cost model + admission control.
2. Add quotas/eviction/TTL for namespaces and objects.
3. Improve audit logging and abuse detection dashboards/alerts.

---

## Quick threat model summary

- **Most likely attacks:** unauthorized writes/deletes, cheap DoS via connection holding, memory amplification via key cardinality, admin reconnaissance.
- **Most damaging attacks:** rogue cluster member poisoning, persistent memory/cost amplification, broad data tampering.
- **Highest ROI fixes:** authN/authZ + mTLS + strict input/resource limits + rate limiting.
