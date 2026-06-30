/**
 * k6 load test — agent ingest endpoint
 *
 * Usage (against local dev stack):
 *   k6 run load-tests/ingest.js
 *
 * Usage (against Railway production — read-only staging run):
 *   BASE_URL=https://backend-production-a9cb4.up.railway.app k6 run \
 *     --env BASE_URL=$BASE_URL load-tests/ingest.js
 *
 * Tuning:
 *   --vus 50 --duration 60s          → steady 50-VU smoke test
 *   --stage 0s:1,30s:50,60s:50,10s:0 → ramp-up / ramp-down
 *
 * What it measures:
 *   - p95 / p99 latency for POST /agents/ingest
 *   - Throughput (events/s accepted by the backend)
 *   - Error rate at increasing concurrency
 *
 * Prerequisites:  npm install -g k6   (or brew install k6)
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// ─── Configuration ────────────────────────────────────────────────────────────

const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";
const API = `${BASE_URL}/api/v1`;

// How many events to pack into each batch request.
// The backend accepts up to 500; 10 gives a realistic per-agent cadence.
const EVENTS_PER_BATCH = parseInt(__ENV.EVENTS_PER_BATCH || "10", 10);

// ─── Custom metrics ───────────────────────────────────────────────────────────

const eventsAccepted = new Counter("events_accepted");
const eventsRejected = new Counter("events_rejected");
const ingestErrors = new Rate("ingest_error_rate");
const ingestLatency = new Trend("ingest_latency_ms", true);

// ─── Test options (override with CLI flags) ───────────────────────────────────

export const options = {
  stages: [
    { duration: "10s", target: 5 },   // warm-up
    { duration: "30s", target: 20 },  // ramp to 20 VUs
    { duration: "60s", target: 20 },  // hold
    { duration: "10s", target: 0 },   // ramp down
  ],
  thresholds: {
    http_req_failed: ["rate<0.01"],        // <1% HTTP errors
    ingest_error_rate: ["rate<0.01"],      // <1% app-level errors
    ingest_latency_ms: ["p(95)<500"],      // p95 under 500 ms
    http_req_duration: ["p(99)<1000"],     // p99 under 1 s
  },
};

// ─── Setup: register user, create tenant, enroll agent ───────────────────────

export function setup() {
  const email = `loadtest-${Date.now()}@example.com`;
  const password = "LoadTest1!Pass";

  // 1. Register
  const regResp = http.post(
    `${API}/auth/register`,
    JSON.stringify({ email, password, full_name: "Load Tester" }),
    { headers: { "Content-Type": "application/json" } },
  );
  if (regResp.status !== 201) {
    throw new Error(`register failed: ${regResp.status} ${regResp.body}`);
  }
  const accessToken = regResp.json("data.access_token");
  const authHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${accessToken}`,
  };

  // 2. Create tenant
  const tenantResp = http.post(
    `${API}/tenants`,
    JSON.stringify({ name: "Load Test Tenant", slug: `load-${Date.now()}` }),
    { headers: authHeaders },
  );
  if (tenantResp.status !== 201) {
    throw new Error(`create tenant failed: ${tenantResp.status} ${tenantResp.body}`);
  }
  const tenantId = tenantResp.json("data.id");
  const fullHeaders = { ...authHeaders, "X-Tenant-ID": tenantId };

  // 3. Enroll agent
  const enrollResp = http.post(
    `${API}/agents/enroll`,
    JSON.stringify({ hostname: "load-test-host", os_type: "linux", agent_version: "1.0.0" }),
    { headers: fullHeaders },
  );
  if (enrollResp.status !== 201) {
    throw new Error(`enroll agent failed: ${enrollResp.status} ${enrollResp.body}`);
  }
  const agentData = enrollResp.json("data");

  return {
    tenantId,
    agentId: agentData.agent_id,
    agentToken: agentData.token,
  };
}

// ─── Main test loop ───────────────────────────────────────────────────────────

export default function (data) {
  const { tenantId, agentId, agentToken } = data;

  const now = new Date().toISOString();
  const events = Array.from({ length: EVENTS_PER_BATCH }, (_, i) => ({
    event_id: `load-${__VU}-${__ITER}-${i}`,
    timestamp: now,
    category: "process",
    hostname: `load-host-${__VU}`,
    os_type: "linux",
    process: {
      pid: 1000 + i,
      name: "bash",
      command_line: `bash -c "echo test-${i}"`,
    },
    raw: { source: "k6-load-test", vu: __VU, iter: __ITER },
  }));

  const payload = JSON.stringify({ events });
  const headers = {
    "Content-Type": "application/json",
    "X-Agent-ID": agentId,
    "X-Agent-Token": agentToken,
    "X-Tenant-ID": tenantId,
  };

  const start = Date.now();
  const resp = http.post(`${API}/agents/ingest`, payload, { headers });
  const elapsed = Date.now() - start;

  ingestLatency.add(elapsed);

  const ok = check(resp, {
    "status 200": (r) => r.status === 200,
    "accepted > 0": (r) => {
      try {
        return r.json("data.accepted") > 0;
      } catch {
        return false;
      }
    },
  });

  if (ok && resp.status === 200) {
    const body = resp.json();
    eventsAccepted.add(body.data?.accepted ?? 0);
    eventsRejected.add(body.data?.rejected ?? 0);
    ingestErrors.add(0);
  } else {
    ingestErrors.add(1);
  }

  // Simulate real agent cadence — one batch every ~1 second per VU
  sleep(1);
}

// ─── Teardown: print summary ──────────────────────────────────────────────────

export function teardown(data) {
  console.log(`Load test complete. Agent ID: ${data.agentId}, Tenant: ${data.tenantId}`);
}
