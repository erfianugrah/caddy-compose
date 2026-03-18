import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Counter, Trend } from "k6/metrics";

// Custom metrics
const blocked = new Rate("blocked_rate");
const jailed = new Rate("jailed_rate");
const errors = new Counter("connection_errors");
const ttfb = new Trend("ttfb_ms");

const TARGET = __ENV.TARGET || "https://httpbun.erfi.io/get";

// Ramp: 0 → 500 VUs over 15s, hold at 500 for 30s, then 1000 for 15s, cooldown
export const options = {
  discardResponseMessageBody: true,
  insecureSkipTLSVerify: false,
  noConnectionReuse: false, // reuse connections like a real attack
  stages: [
    { duration: "10s", target: 200 },  // warm up
    { duration: "10s", target: 500 },  // ramp to medium
    { duration: "20s", target: 1000 }, // sustained high load
    { duration: "15s", target: 2000 }, // push hard
    { duration: "5s", target: 0 },     // cooldown
  ],
  thresholds: {
    // We EXPECT to get blocked — these are informational, not pass/fail
    http_req_duration: ["p(50)<5000"],
  },
};

export default function () {
  const res = http.get(TARGET, {
    headers: {
      "User-Agent": "k6-ddos-test/1.0",
      "Accept": "text/html",
    },
    timeout: "10s",
  });

  if (res.error) {
    errors.add(1);
    return;
  }

  const is403 = res.status === 403;
  const isReset = res.status === 0; // connection reset = nftables drop or TCP RST

  blocked.add(is403);
  jailed.add(isReset);

  if (res.timings && res.timings.waiting) {
    ttfb.add(res.timings.waiting);
  }

  // Log phase transitions
  if (is403 && __ITER % 100 === 0) {
    console.log(`[${new Date().toISOString()}] 403 blocked — L7 jail active`);
  }
  if (isReset && __ITER % 100 === 0) {
    console.log(`[${new Date().toISOString()}] conn reset — L3/L4 drop active`);
  }
}
