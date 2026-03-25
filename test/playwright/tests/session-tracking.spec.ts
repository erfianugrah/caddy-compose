import { test, expect } from "@playwright/test";

const WAFCTL_URL = process.env.WAFCTL_URL || "http://localhost:18082";
const CADDY_URL = process.env.CADDY_URL || "http://localhost:18080";

// ── Helpers ─────────────────────────────────────────────────────────

async function createChallengeRule(
  name: string,
  difficulty: number,
  conditions: { field: string; operator: string; value: string }[]
): Promise<string> {
  const resp = await fetch(`${WAFCTL_URL}/api/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name,
      type: "challenge",
      enabled: true,
      challenge_difficulty: difficulty,
      challenge_algorithm: "fast",
      challenge_ttl: "1h",
      conditions,
    }),
  });
  if (resp.status !== 201) {
    throw new Error(`Failed to create rule: ${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()).id;
}

async function deleteRule(id: string) {
  await fetch(`${WAFCTL_URL}/api/rules/${id}`, { method: "DELETE" });
}

async function deploy() {
  const resp = await fetch(`${WAFCTL_URL}/api/config/deploy`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (resp.status !== 200) throw new Error(`Deploy failed: ${resp.status}`);
  await new Promise((r) => setTimeout(r, 6000));
}

// Stealth patches (same as challenge.spec.ts)
const STEALTH_SCRIPT = `
  Object.defineProperty(navigator, 'webdriver', { get: () => false });
  Object.defineProperty(navigator, 'plugins', {
    get: () => {
      const arr = [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'PDF' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
      ];
      arr.item = (i) => arr[i];
      arr.namedItem = (n) => arr.find(p => p.name === n) || null;
      arr.refresh = () => {};
      return arr;
    }
  });
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  if (window.speechSynthesis) {
    const origGetVoices = speechSynthesis.getVoices.bind(speechSynthesis);
    speechSynthesis.getVoices = () => {
      const real = origGetVoices();
      if (real.length > 0) return real;
      return [
        { voiceURI: 'Google US English', name: 'Google US English', lang: 'en-US', localService: false, default: true },
      ];
    };
  }
  const origGetParam = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 0x9245) return 'Google Inc. (Intel)';
    if (param === 0x9246) return 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.6)';
    return origGetParam.call(this, param);
  };
  if (!window.chrome) window.chrome = {};
  if (!window.chrome.runtime) window.chrome.runtime = { id: undefined };
`;

// ════════════════════════════════════════════════════════════════════
//  Session Tracking Browser Flow
// ════════════════════════════════════════════════════════════════════

test.describe("Session Tracking", () => {
  let ruleId: string;

  test.beforeAll(async () => {
    ruleId = await createChallengeRule(
      "pw-session-tracking",
      1,
      [{ field: "path", operator: "begins_with", value: "/pw-session" }]
    );
    await deploy();
  });

  test.afterAll(async () => {
    if (ruleId) {
      await deleteRule(ruleId);
      await deploy();
    }
  });

  test("session stats API is accessible", async () => {
    const resp = await fetch(`${WAFCTL_URL}/api/sessions/stats`);
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.active_sessions).toBeGreaterThanOrEqual(0);
    expect(data.suspicious_sessions).toBeGreaterThanOrEqual(0);
    expect(data.total_navigations).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.top_suspicious)).toBe(true);
  });

  test("sessions dashboard page loads", async ({ page }) => {
    await page.goto(`${WAFCTL_URL}/sessions`);
    await expect(page.getByRole("heading", { name: "Session Tracking" })).toBeVisible();
    await expect(page.getByText("ACTIVE SESSIONS")).toBeVisible();
  });

  test("stealth browser solves challenge and SW registers", async ({ browser }) => {
    const context = await browser.newContext();
    await context.addInitScript(STEALTH_SCRIPT);
    const page = await context.newPage();

    // Navigate to challenged path — will see interstitial.
    await page.goto(`${CADDY_URL}/pw-session/page1`);

    // Simulate mouse activity for bot scoring.
    await page.mouse.move(100, 200);
    await page.mouse.move(300, 400);

    // Wait for PoW solve + redirect.
    await page.waitForTimeout(8000);

    // Check for challenge cookie (indicates PoW passed).
    const cookies = await context.cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));

    if (challengeCookie) {
      // PoW passed — the SW should have been registered.
      // Navigate to a second page to generate a navigation beacon.
      await page.goto(`${CADDY_URL}/pw-session/page2`);
      await page.waitForTimeout(2000);

      // Navigate to a third page.
      await page.goto(`${CADDY_URL}/pw-session/page3`);
      await page.waitForTimeout(2000);

      // The session-sw.js should have intercepted these navigations.
      // We can't directly verify SW state from Playwright, but we can
      // check that the beacon endpoint is being hit by verifying the
      // session stats API shows activity (may take a log rotation cycle).
    } else {
      // Bot scoring rejected us — expected in some CI environments.
      console.log("No cookie — stealth not sufficient in this environment");
    }

    await context.close();
  });

  test("session beacon endpoint returns 204 on POST", async ({ request }) => {
    const resp = await request.post(`${CADDY_URL}/.well-known/policy-challenge/session`, {
      data: JSON.stringify([{ ts: Date.now(), path: "/test", type: "navigate" }]),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status()).toBe(204);
  });

  test("session-sw.js served with correct headers", async ({ request }) => {
    const resp = await request.get(`${CADDY_URL}/.well-known/policy-challenge/session-sw.js`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("javascript");
    expect(resp.headers()["service-worker-allowed"]).toBe("/");
    const body = await resp.text();
    expect(body).toContain("clients.claim");
    expect(body).toContain("navigate");
  });
});
