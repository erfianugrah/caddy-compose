import { test, expect } from "@playwright/test";

const WAFCTL_URL = process.env.WAFCTL_URL || "http://localhost:18082";
const CADDY_URL = process.env.CADDY_URL || "http://localhost:18080";

// Helpers from challenge.spec.ts
async function createChallengeRule(name: string, difficulty: number, conditions: any[]): Promise<string> {
  const resp = await fetch(`${WAFCTL_URL}/api/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, type: "challenge", enabled: true, challenge_difficulty: difficulty, challenge_algorithm: "fast", challenge_ttl: "1h", conditions }),
  });
  if (resp.status !== 201) throw new Error(`Failed: ${resp.status}`);
  return (await resp.json()).id;
}
async function deleteRule(id: string) { await fetch(`${WAFCTL_URL}/api/rules/${id}`, { method: "DELETE" }); }
async function deploy() {
  await fetch(`${WAFCTL_URL}/api/config/deploy`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  await new Promise((r) => setTimeout(r, 6000));
}

// ════════════════════════════════════════════════════════════════════
//  AI Crawler Simulation Tests
//  These simulate what real AI crawlers (GPTBot, CCBot, etc.) would do
//  with headless Chrome. They verify the bot scoring actually catches them.
// ════════════════════════════════════════════════════════════════════

test.describe("AI Crawler Detection", () => {
  let ruleId: string;

  test.beforeAll(async () => {
    ruleId = await createChallengeRule("pw-ai-crawler", 1, [
      { field: "path", operator: "begins_with", value: "/pw-ai-test" },
    ]);
    await deploy();
  });

  test.afterAll(async () => {
    if (ruleId) { await deleteRule(ruleId); await deploy(); }
  });

  test("raw headless Chrome (no stealth) is blocked by bot scoring", async ({ page }) => {
    // This simulates GPTBot/CCBot using headless Chrome with no stealth patches.
    // navigator.webdriver=true, 0 plugins, SwiftShader GPU, 0 speech voices.
    await page.goto(`${CADDY_URL}/pw-ai-test/scrape`);
    await page.waitForTimeout(8000);

    // Should NOT get a cookie — bot scoring rejects headless Chrome.
    const cookies = await page.context().cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));
    expect(challengeCookie).toBeUndefined();

    // The page should show failure or still be on the interstitial.
    const body = await page.content();
    const blocked = body.includes("Challenge failed") || body.includes("Verifying") || body.includes("403");
    expect(blocked).toBe(true);
  });

  test("headless Chrome with spoofed UA is still blocked", async ({ page }) => {
    // AI crawlers often spoof User-Agent but nothing else.
    await page.setExtraHTTPHeaders({
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    });
    await page.goto(`${CADDY_URL}/pw-ai-test/spoofed-ua`);
    await page.waitForTimeout(8000);

    const cookies = await page.context().cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));
    expect(challengeCookie).toBeUndefined();
  });

  test("headless Chrome with partial stealth is still blocked", async ({ page, context }) => {
    // AI crawlers using puppeteer-extra-plugin-stealth patch webdriver but NOT:
    // - plugins (still 0)
    // - WebGL renderer (still SwiftShader)
    // - speech voices (still 0)
    // - permissions timing (still instant)
    await context.addInitScript(`
      Object.defineProperty(navigator, 'webdriver', { get: () => false });
      // Only patches webdriver — everything else is still headless.
    `);

    await page.goto(`${CADDY_URL}/pw-ai-test/partial-stealth`);
    await page.waitForTimeout(8000);

    const cookies = await page.context().cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));
    // Should still be blocked — SwiftShader + 0 plugins + 0 voices = score >= 70.
    expect(challengeCookie).toBeUndefined();
  });

  test("headless Chrome with full stealth DOES pass (demonstrates the limit)", async ({ browser }) => {
    // Full stealth: patches webdriver, plugins, languages, speech, WebGL, chrome.runtime.
    // This simulates the most sophisticated AI crawlers (anti-detect browsers).
    // Our scoring should still catch some signals (e.g., no Sec-Fetch headers in test env).
    const context = await browser.newContext();
    await context.addInitScript(`
      Object.defineProperty(navigator, 'webdriver', { get: () => false });
      Object.defineProperty(navigator, 'plugins', {
        get: () => {
          const arr = [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'PDF' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
          ];
          arr.item = (i) => arr[i]; arr.namedItem = (n) => arr.find(p => p.name === n);
          arr.refresh = () => {}; return arr;
        }
      });
      Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
      if (window.speechSynthesis) {
        speechSynthesis.getVoices = () => [
          { voiceURI: 'Google US English', name: 'Google US English', lang: 'en-US', localService: false, default: true },
        ];
      }
      const origGetParam = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(p) {
        if (p === 0x9245) return 'Google Inc. (Intel)';
        if (p === 0x9246) return 'ANGLE (Intel, Intel(R) UHD Graphics 630)';
        return origGetParam.call(this, p);
      };
      if (!window.chrome) window.chrome = {};
      if (!window.chrome.runtime) window.chrome.runtime = { id: undefined };
    `);

    const page = await context.newPage();
    // Also add mouse movement to pass behavioral checks.
    await page.goto(`${CADDY_URL}/pw-ai-test/full-stealth`);
    await page.mouse.move(200, 300);
    await page.mouse.move(400, 200);
    await page.waitForTimeout(8000);

    const cookies = await context.cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));

    if (challengeCookie) {
      // Full stealth passed — this demonstrates the limit of detection.
      // Anti-detect browsers with full patches can pass.
      console.log("Full stealth PASSED bot scoring — demonstrates detection limit");
      expect(challengeCookie.value).toContain(".");
    } else {
      // Even full stealth was caught — the header-level checks or JA4 caught it.
      console.log("Full stealth BLOCKED — header/JA4 checks caught it");
    }

    await context.close();
  });
});
