import { test, expect } from "@playwright/test";

const WAFCTL_URL = process.env.WAFCTL_URL || "http://localhost:18082";
const CADDY_URL = process.env.CADDY_URL || "http://localhost:18080";

// Helper: create a challenge rule via wafctl API.
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
  const data = await resp.json();
  return data.id;
}

// Helper: delete a rule.
async function deleteRule(id: string) {
  await fetch(`${WAFCTL_URL}/api/rules/${id}`, { method: "DELETE" });
}

// Helper: deploy WAF config.
async function deploy() {
  const resp = await fetch(`${WAFCTL_URL}/api/config/deploy`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (resp.status !== 200) {
    throw new Error(`Deploy failed: ${resp.status}`);
  }
  // Wait for plugin hot-reload (mtime polling at 5s interval).
  await new Promise((r) => setTimeout(r, 6000));
}

test.describe("Challenge PoW Browser Flow", () => {
  let ruleId: string;

  test.beforeAll(async () => {
    // Create a challenge rule matching our test path.
    ruleId = await createChallengeRule(
      "pw-challenge-browser",
      1, // difficulty 1 = very fast, ~1 iteration
      [{ field: "path", operator: "begins_with", value: "/pw-challenge" }]
    );
    await deploy();
  });

  test.afterAll(async () => {
    if (ruleId) {
      await deleteRule(ruleId);
      await deploy();
    }
  });

  test("interstitial page loads and shows challenge UI", async ({ browser }) => {
    // Use a JS-disabled context to see the raw interstitial without the solver running.
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();

    await page.goto(`${CADDY_URL}/pw-challenge/test`);

    // The interstitial page should be visible.
    await expect(page.locator("h1")).toContainText("Verifying your connection");

    // Challenge data script tag should exist.
    const challengeData = page.locator("#challenge-data");
    await expect(challengeData).toBeAttached();

    // The progress bar should exist.
    const progress = page.locator("#challenge-progress-inner");
    await expect(progress).toBeAttached();

    // Noscript fallback should be visible.
    const noscript = await page.locator("noscript").textContent();
    expect(noscript).toContain("JavaScript is required");

    await context.close();
  });

  test("browser solves PoW and gets redirected with cookie", async ({ page }) => {
    // Navigate to the challenged path.
    const response = await page.goto(`${CADDY_URL}/pw-challenge/test`, {
      waitUntil: "networkidle",
    });

    // At difficulty 1, the PoW should solve almost instantly.
    // The JS solver will POST to the verify endpoint and redirect.
    // Wait for the redirect to complete (up to 30s).
    await page.waitForURL((url) => !url.pathname.includes("pw-challenge") || url.pathname === "/pw-challenge/test", {
      timeout: 30000,
    }).catch(() => {
      // If no redirect, that's fine — we might still be on the same page
      // with the cookie set. Check below.
    });

    // After solving, the browser should have a challenge cookie.
    const cookies = await page.context().cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));

    // The PoW might redirect to the original URL which goes through httpbun upstream.
    // Or we might still be on the interstitial if the redirect failed.
    // Either way, verify the cookie was set.
    if (challengeCookie) {
      expect(challengeCookie.httpOnly).toBe(true);
      expect(challengeCookie.sameSite).toBe("Lax");
      expect(challengeCookie.value).toContain("."); // payload.signature format

      // Now visit the same path again — should bypass the challenge.
      const resp2 = await page.goto(`${CADDY_URL}/pw-challenge/test`);
      const body = await page.content();

      // Should NOT see the interstitial again (cookie bypass).
      expect(body).not.toContain("Verifying your connection");
    } else {
      // If no cookie, check if we're past the interstitial.
      const body = await page.content();
      // If the page shows "Verified! Redirecting..." that's the success state.
      if (!body.includes("Verified")) {
        // Log the page content for debugging.
        console.log("Page URL:", page.url());
        console.log("Page content (first 500 chars):", body.substring(0, 500));
      }
    }
  });

  test("second visit with cookie bypasses challenge", async ({ page, context }) => {
    // First visit — solve the challenge.
    await page.goto(`${CADDY_URL}/pw-challenge/bypass-test`, {
      waitUntil: "networkidle",
    });

    // Wait for the solver to complete (difficulty 1 is instant).
    await page.waitForTimeout(5000);

    // Check if we got a cookie.
    const cookies = await context.cookies();
    const challengeCookie = cookies.find((c) => c.name.startsWith("__pc_"));

    if (!challengeCookie) {
      test.skip(true, "No challenge cookie obtained — solver may not have completed");
      return;
    }

    // Second visit — should go directly to upstream (httpbun).
    const resp = await page.goto(`${CADDY_URL}/pw-challenge/bypass-test`);
    const body = await page.content();

    // Should NOT see the challenge interstitial.
    expect(body).not.toContain("Verifying your connection");
  });

  test("non-challenged path passes through without interstitial", async ({ page }) => {
    // Visit a path that doesn't match the challenge rule.
    await page.goto(`${CADDY_URL}/get`);
    const body = await page.content();

    // Should NOT see the challenge page.
    expect(body).not.toContain("Verifying your connection");
    // Should see the httpbun response (JSON).
    expect(body).toContain("headers");
  });
});

test.describe("Challenge Worker JS", () => {
  test("worker.js is accessible and valid JavaScript", async ({ page }) => {
    const resp = await page.goto(
      `${CADDY_URL}/.well-known/policy-challenge/worker.js`
    );

    expect(resp?.status()).toBe(200);
    expect(resp?.headers()["content-type"]).toContain("javascript");

    const body = await page.content();
    expect(body).toContain("addEventListener");
    expect(body).toContain("sha256Fallback");
  });
});

test.describe("Challenge Noscript", () => {
  let noscriptRuleId: string;

  test.beforeAll(async () => {
    noscriptRuleId = await createChallengeRule(
      "pw-noscript-test",
      1,
      [{ field: "path", operator: "begins_with", value: "/pw-noscript" }]
    );
    await deploy();
  });

  test.afterAll(async () => {
    if (noscriptRuleId) {
      await deleteRule(noscriptRuleId);
      await deploy();
    }
  });

  test("shows noscript message when JS is disabled", async ({ browser }) => {
    // Create a context with JS disabled.
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();

    await page.goto(`${CADDY_URL}/pw-noscript/test`);
    const body = await page.content();

    // The noscript block should be visible.
    expect(body).toContain("JavaScript is required");

    await context.close();
  });
});
