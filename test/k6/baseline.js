// baseline.js — Simulate realistic user browsing to build the DDoS mitigator's
// statistical baseline. This must run BEFORE the attack scenario so the Welford
// stats engine has enough diverse observations (>1000) to produce meaningful
// z-scores.
//
// Pattern: 20 VUs browsing 50+ different pages with varied timing, simulating
// a real website with multiple services and endpoints.

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const errorRate = new Rate("errors");

const BASE_URL = __ENV.TARGET_URL || "http://caddy:8080";

// Diverse paths that simulate real browsing across multiple services
const paths = [
  "/get",
  "/headers",
  "/ip",
  "/user-agent",
  "/status/200",
  "/status/201",
  "/status/204",
  "/response-headers?Content-Type=application/json",
  "/anything",
  "/anything/page/1",
  "/anything/page/2",
  "/anything/page/3",
  "/anything/api/users",
  "/anything/api/posts",
  "/anything/api/comments",
  "/anything/search?q=hello",
  "/anything/search?q=world",
  "/anything/search?q=test",
  "/anything/dashboard",
  "/anything/settings",
  "/anything/profile",
  "/anything/login",
  "/anything/logout",
  "/anything/register",
  "/anything/forgot-password",
  "/anything/about",
  "/anything/contact",
  "/anything/help",
  "/anything/docs",
  "/anything/docs/api",
  "/anything/docs/getting-started",
  "/anything/blog",
  "/anything/blog/post-1",
  "/anything/blog/post-2",
  "/anything/blog/post-3",
  "/anything/media/image.jpg",
  "/anything/media/video.mp4",
  "/anything/static/styles.css",
  "/anything/static/app.js",
  "/anything/favicon.ico",
  "/anything/robots.txt",
  "/anything/sitemap.xml",
  "/anything/.well-known/security.txt",
  "/anything/api/v1/health",
  "/anything/api/v1/status",
  "/anything/api/v2/users?page=1",
  "/anything/api/v2/users?page=2",
  "/anything/api/v2/posts?limit=10",
  "/anything/api/v2/posts?limit=20&offset=10",
  "/anything/feed/rss",
];

// Varied user agents to diversify fingerprints
const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
  "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
  "curl/8.5.0",
  "Googlebot/2.1 (+http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
];

export const options = {
  scenarios: {
    // Ramp up users gradually — must generate >1000 observations to activate
    // the DDoS mitigator's z-score engine (minObservationsForZScore=1000).
    browsing: {
      executor: "ramping-vus",
      startVUs: 5,
      stages: [
        { duration: "15s", target: 20 },  // warm up
        { duration: "30s", target: 30 },  // sustained browsing
        { duration: "15s", target: 10 },  // quiet period
        { duration: "15s", target: 25 },  // pick up again
      ],
      gracefulRampDown: "5s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],  // <1% errors (all should pass)
    http_req_duration: ["p(95)<2000"], // 95th percentile under 2s
    errors: ["rate<0.01"],
  },
};

export default function () {
  // Pick a random path and user agent
  const path = paths[Math.floor(Math.random() * paths.length)];
  const ua = userAgents[Math.floor(Math.random() * userAgents.length)];

  const res = http.get(`${BASE_URL}${path}`, {
    headers: {
      "User-Agent": ua,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      "Referer": `${BASE_URL}/`,
      "Connection": "keep-alive",
    },
  });

  const ok = check(res, {
    "status is not 403": (r) => r.status !== 403,
    "status is not 429": (r) => r.status !== 429,
  });
  errorRate.add(!ok);

  // Think time: 0.3–1.5 seconds (faster than real browsing to hit 1000+ observations)
  sleep(0.3 + Math.random() * 1.2);
}
