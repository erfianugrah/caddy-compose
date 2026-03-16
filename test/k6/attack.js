// attack.js — Simulate a DDoS attack pattern to test the mitigator's
// auto-jail behavior. Runs AFTER baseline.js has seeded enough observations.
//
// Pattern: Many VUs hammering a single endpoint with identical fingerprints
// (same path, same method, same UA). This should trigger the z-score threshold
// and result in auto-jail → 403 responses.
//
// Success criteria:
// - Initially requests pass (200)
// - After enough requests, mitigator detects the anomaly and starts returning 403
// - The 403 rate should climb as the attacker gets jailed

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Counter, Trend } from "k6/metrics";

const blocked = new Rate("blocked_rate");
const total403 = new Counter("total_403");
const total200 = new Counter("total_200");
const timeToBlock = new Trend("time_to_first_block");

const BASE_URL = __ENV.TARGET_URL || "http://caddy-e2e:8080";
const ATTACK_PATH = __ENV.ATTACK_PATH || "/anything/api/v1/vulnerable-endpoint";

// Single user agent to maximize fingerprint collision
const ATTACK_UA = "attack-bot/1.0 (DDoS simulation)";

let firstBlockTime = 0;
let testStartTime = 0;

export const options = {
  scenarios: {
    // Phase 1: Light probe (looks normal, 5 VUs)
    probe: {
      executor: "constant-vus",
      vus: 5,
      duration: "5s",
      startTime: "0s",
      env: { PHASE: "probe" },
    },
    // Phase 2: Ramp up attack (30 VUs → 100 VUs)
    flood: {
      executor: "ramping-vus",
      startVUs: 10,
      stages: [
        { duration: "5s", target: 30 },
        { duration: "10s", target: 50 },
        { duration: "10s", target: 100 },
        { duration: "5s", target: 100 },  // sustain
      ],
      startTime: "5s",
      env: { PHASE: "flood" },
    },
  },
  thresholds: {
    // We EXPECT 403s during attack — the threshold checks that blocking happens
    blocked_rate: ["rate>0.1"],  // At least 10% of flood requests should be blocked
  },
};

export function setup() {
  // Verify the target is reachable before starting
  const res = http.get(`${BASE_URL}/get`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; k6-setup/1.0)",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      "Referer": `${BASE_URL}/`,
    },
  });
  check(res, { "target reachable": (r) => r.status === 200 });
  return { startTime: Date.now() };
}

export default function (data) {
  if (!testStartTime) testStartTime = data.startTime;

  const res = http.get(`${BASE_URL}${ATTACK_PATH}`, {
    headers: {
      "User-Agent": ATTACK_UA,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      "Referer": `${BASE_URL}/`,
      "Connection": "keep-alive",
    },
  });

  const isBlocked = res.status === 403;
  blocked.add(isBlocked);

  if (isBlocked) {
    total403.add(1);
    if (!firstBlockTime) {
      firstBlockTime = Date.now();
      timeToBlock.add(firstBlockTime - testStartTime);
    }
  } else {
    total200.add(1);
  }

  // Minimal delay — we're simulating an aggressive attacker
  sleep(0.01 + Math.random() * 0.05);
}

export function teardown(data) {
  console.log(`Attack simulation complete.`);
  if (firstBlockTime) {
    console.log(`First block after ${firstBlockTime - data.startTime}ms`);
  } else {
    console.log(`WARNING: No blocks detected — mitigator may not have triggered`);
  }
}
