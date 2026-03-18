import http from "k6/http";
import { Rate, Counter } from "k6/metrics";

const blocked = new Rate("blocked_rate");
const jailed = new Rate("jailed_rate");
const errors = new Counter("connection_errors");

const TARGET = __ENV.TARGET || "https://httpbun.erfi.io/get";

// Sustained 30K RPS: high VU count, minimal sleep
export const options = {
  insecureSkipTLSVerify: false,
  noConnectionReuse: false,
  batch: 10,
  stages: [
    { duration: "5s", target: 3000 },   // fast ramp
    { duration: "30s", target: 5000 },   // sustain — k6 will max out connections
    { duration: "5s", target: 0 },       // cooldown
  ],
  thresholds: {
    http_req_duration: ["p(50)<10000"],
  },
};

export default function () {
  const res = http.get(TARGET, {
    headers: {
      "User-Agent": "k6-30k-rps/1.0",
      "Accept": "text/html",
    },
    timeout: "5s",
  });

  if (res.error) {
    errors.add(1);
    return;
  }

  blocked.add(res.status === 403);
  jailed.add(res.status === 0);
}
