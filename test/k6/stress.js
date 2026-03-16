// stress.js — Aggressive multi-phase DDoS load test.
// Phase 1: Diverse baseline (seed behavioral profiles, 30s)
// Phase 2: Concentrated flood ramp (trigger auto-jail, 30s)
// Phase 3: Max pressure sustained flood (verify jail holds, 60s)
//
// Run: k6 run --out json=/tmp/k6-results.json test/k6/stress.js
// Or via e2e: DDOS_LOAD=1 make test-e2e-load

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Counter, Trend } from "k6/metrics";

const blocked = new Rate("blocked_rate");
const total403 = new Counter("total_403");
const total200 = new Counter("total_200");
const timeToBlock = new Trend("time_to_first_block");

const BASE_URL = __ENV.TARGET_URL || "http://caddy:8080";
const ATTACK_PATH = __ENV.ATTACK_PATH || "/anything/api/v1/stress-target";

const paths = [
  "/get", "/headers", "/ip", "/user-agent", "/status/200", "/status/201",
  "/anything", "/anything/page/1", "/anything/page/2", "/anything/page/3",
  "/anything/api/users", "/anything/api/posts", "/anything/api/comments",
  "/anything/search?q=hello", "/anything/search?q=world", "/anything/search?q=test",
  "/anything/dashboard", "/anything/settings", "/anything/profile",
  "/anything/docs", "/anything/blog/1", "/anything/blog/2",
  "/anything/static/app.js", "/anything/favicon.ico", "/anything/robots.txt",
  "/anything/api/v1/health", "/anything/api/v2/users?page=1",
  "/anything/feed/rss", "/anything/about", "/anything/contact",
];

const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
  "Accept-Encoding": "gzip, deflate, br",
  "Connection": "keep-alive",
};

let firstBlockTime = 0;

export const options = {
  scenarios: {
    baseline: {
      executor: "ramping-vus",
      startVUs: 10,
      stages: [
        { duration: "10s", target: 30 },
        { duration: "20s", target: 50 },
      ],
      startTime: "0s",
      exec: "baseline",
    },
    flood_ramp: {
      executor: "ramping-vus",
      startVUs: 20,
      stages: [
        { duration: "10s", target: 100 },
        { duration: "20s", target: 200 },
      ],
      startTime: "30s",
      exec: "flood",
    },
    flood_sustain: {
      executor: "constant-vus",
      vus: 300,
      duration: "60s",
      startTime: "60s",
      exec: "flood",
    },
  },
};

export function setup() {
  const ref = `${BASE_URL}/`;
  const res = http.get(`${BASE_URL}/get`, {
    headers: { ...BROWSER_HEADERS, "Referer": ref },
  });
  check(res, { "setup: target reachable": (r) => r.status === 200 });
  return { startTime: Date.now() };
}

export function baseline() {
  const path = paths[Math.floor(Math.random() * paths.length)];
  const ref = `${BASE_URL}/`;
  const res = http.get(`${BASE_URL}${path}`, {
    headers: { ...BROWSER_HEADERS, "Referer": ref },
  });
  check(res, { "baseline: not blocked": (r) => r.status !== 403 });
  sleep(0.1 + Math.random() * 0.5);
}

export function flood(data) {
  const ref = `${BASE_URL}/`;
  const res = http.get(`${BASE_URL}${ATTACK_PATH}`, {
    headers: {
      ...BROWSER_HEADERS,
      "User-Agent": "flood-bot/1.0 (k6 stress test)",
      "Referer": ref,
    },
  });

  const isBlocked = res.status === 403;
  blocked.add(isBlocked);
  if (isBlocked) {
    total403.add(1);
    if (!firstBlockTime) {
      firstBlockTime = Date.now();
      timeToBlock.add(firstBlockTime - data.startTime);
    }
  } else {
    total200.add(1);
  }
  // Zero delay — max aggression
}

export function teardown(data) {
  const elapsed = (Date.now() - data.startTime) / 1000;
  console.log(`Stress test: ${elapsed.toFixed(0)}s elapsed`);
  if (firstBlockTime) {
    console.log(`First DDoS block at ${((firstBlockTime - data.startTime) / 1000).toFixed(1)}s`);
  } else {
    console.log("WARNING: No DDoS blocks detected (mitigator may not have triggered)");
  }
}
