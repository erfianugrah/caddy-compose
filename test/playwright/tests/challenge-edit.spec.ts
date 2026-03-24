import { test, expect } from "@playwright/test";

const WAFCTL_URL = process.env.WAFCTL_URL || "http://localhost:18082";
const CADDY_URL = process.env.CADDY_URL || "http://localhost:18080";

async function apiPost(path: string, body: any) {
  const resp = await fetch(`${WAFCTL_URL}${path}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  return { status: resp.status, data: await resp.json() };
}
async function apiPut(path: string, body: any) {
  const resp = await fetch(`${WAFCTL_URL}${path}`, {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  return { status: resp.status, data: await resp.json() };
}
async function apiGet(path: string) {
  const resp = await fetch(`${WAFCTL_URL}${path}`);
  return { status: resp.status, data: await resp.json() };
}
async function apiDelete(path: string) {
  await fetch(`${WAFCTL_URL}${path}`, { method: "DELETE" });
}
async function deploy() {
  await fetch(`${WAFCTL_URL}/api/config/deploy`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  });
  await new Promise(r => setTimeout(r, 6000));
}

test.describe("Challenge Rule Edit Flow", () => {
  let ruleId: string;

  test.afterAll(async () => {
    if (ruleId) { await apiDelete(`/api/rules/${ruleId}`); await deploy(); }
  });

  test("create → edit difficulty → deploy → verify interstitial reflects change", async ({ browser }) => {
    // 1. Create with difficulty 1
    const create = await apiPost("/api/rules", {
      name: "pw-edit-test",
      type: "challenge",
      enabled: true,
      challenge_difficulty: 1,
      challenge_algorithm: "fast",
      challenge_ttl: "1h",
      conditions: [{ field: "path", operator: "begins_with", value: "/pw-edit" }],
    });
    expect(create.status).toBe(201);
    ruleId = create.data.id;
    expect(create.data.challenge_difficulty).toBe(1);

    await deploy();

    // 2. Verify interstitial shows difficulty 1
    const context1 = await browser.newContext({ javaScriptEnabled: false });
    const page1 = await context1.newPage();
    await page1.goto(`${CADDY_URL}/pw-edit/test`);
    const body1 = await page1.content();
    const match1 = body1.match(/"difficulty"\s*:\s*(\d+)/);
    expect(match1).not.toBeNull();
    expect(match1![1]).toBe("1");
    await context1.close();

    // 3. Update difficulty to 6 via API
    const update = await apiPut(`/api/rules/${ruleId}`, {
      challenge_difficulty: 6,
      challenge_algorithm: "slow",
    });
    expect(update.status).toBe(200);
    expect(update.data.challenge_difficulty).toBe(6);
    expect(update.data.challenge_algorithm).toBe("slow");

    // 4. Verify the stored rule reflects the change
    const get = await apiGet(`/api/rules/${ruleId}`);
    expect(get.data.challenge_difficulty).toBe(6);
    expect(get.data.challenge_algorithm).toBe("slow");

    // 5. Deploy and wait for hot-reload
    await deploy();

    // 6. Verify interstitial now shows difficulty 6 and slow algorithm
    const context2 = await browser.newContext({ javaScriptEnabled: false });
    const page2 = await context2.newPage();
    await page2.goto(`${CADDY_URL}/pw-edit/test`);
    const body2 = await page2.content();

    const matchDiff = body2.match(/"difficulty"\s*:\s*(\d+)/);
    expect(matchDiff).not.toBeNull();
    expect(matchDiff![1]).toBe("6");

    const matchAlgo = body2.match(/"algorithm"\s*:\s*"(\w+)"/);
    expect(matchAlgo).not.toBeNull();
    expect(matchAlgo![1]).toBe("slow");

    await context2.close();

    // 7. Update back to difficulty 4, fast
    const update2 = await apiPut(`/api/rules/${ruleId}`, {
      challenge_difficulty: 4,
      challenge_algorithm: "fast",
    });
    expect(update2.status).toBe(200);
    expect(update2.data.challenge_difficulty).toBe(4);
    expect(update2.data.challenge_algorithm).toBe("fast");

    await deploy();

    // 8. Verify interstitial reflects the second change
    const context3 = await browser.newContext({ javaScriptEnabled: false });
    const page3 = await context3.newPage();
    await page3.goto(`${CADDY_URL}/pw-edit/test`);
    const body3 = await page3.content();

    const matchDiff3 = body3.match(/"difficulty"\s*:\s*(\d+)/);
    expect(matchDiff3).not.toBeNull();
    expect(matchDiff3![1]).toBe("4");

    const matchAlgo3 = body3.match(/"algorithm"\s*:\s*"(\w+)"/);
    expect(matchAlgo3).not.toBeNull();
    expect(matchAlgo3![1]).toBe("fast");

    await context3.close();
  });
});

// ════════════════════════════════════════════════════════════════════
//  Adaptive Difficulty Edit Flow
// ════════════════════════════════════════════════════════════════════

test.describe("Adaptive Difficulty Edit Flow", () => {
  let ruleId: string;

  test.afterAll(async () => {
    if (ruleId) { await apiDelete(`/api/rules/${ruleId}`); await deploy(); }
  });

  test("create with adaptive range → deploy → verify difficulty is within range", async ({ browser }) => {
    // Create with min=2, max=6 — the plugin selects adaptively.
    const create = await apiPost("/api/rules", {
      name: "pw-adaptive-test",
      type: "challenge",
      enabled: true,
      challenge_difficulty: 4,
      challenge_min_difficulty: 2,
      challenge_max_difficulty: 6,
      challenge_algorithm: "fast",
      challenge_ttl: "1h",
      conditions: [{ field: "path", operator: "begins_with", value: "/pw-adaptive" }],
    });
    expect(create.status).toBe(201);
    ruleId = create.data.id;
    expect(create.data.challenge_min_difficulty).toBe(2);
    expect(create.data.challenge_max_difficulty).toBe(6);

    await deploy();

    // Fetch interstitial with JS disabled — verify difficulty is in [2, 6].
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();
    await page.goto(`${CADDY_URL}/pw-adaptive/test`);
    const body = await page.content();

    const matchDiff = body.match(/"difficulty"\s*:\s*(\d+)/);
    expect(matchDiff).not.toBeNull();
    const diff = parseInt(matchDiff![1]);
    expect(diff).toBeGreaterThanOrEqual(2);
    expect(diff).toBeLessThanOrEqual(6);

    await context.close();

    // Update to static difficulty (remove adaptive range).
    const update = await apiPut(`/api/rules/${ruleId}`, {
      challenge_min_difficulty: 0,
      challenge_max_difficulty: 0,
      challenge_difficulty: 5,
    });
    expect(update.status).toBe(200);

    await deploy();

    // Verify interstitial now shows exactly difficulty 5.
    const context2 = await browser.newContext({ javaScriptEnabled: false });
    const page2 = await context2.newPage();
    await page2.goto(`${CADDY_URL}/pw-adaptive/test`);
    const body2 = await page2.content();

    const matchDiff2 = body2.match(/"difficulty"\s*:\s*(\d+)/);
    expect(matchDiff2).not.toBeNull();
    expect(matchDiff2![1]).toBe("5");

    await context2.close();
  });
});

// ════════════════════════════════════════════════════════════════════
//  JA4 Token Binding Edit Flow
// ════════════════════════════════════════════════════════════════════

test.describe("JA4 Token Binding Edit Flow", () => {
  let ruleId: string;

  test.afterAll(async () => {
    if (ruleId) { await apiDelete(`/api/rules/${ruleId}`); await deploy(); }
  });

  test("create with bind_ja4 → verify persisted → update → verify change", async () => {
    // Create with bind_ja4=true.
    const create = await apiPost("/api/rules", {
      name: "pw-ja4-binding-test",
      type: "challenge",
      enabled: true,
      challenge_difficulty: 1,
      challenge_bind_ja4: true,
      conditions: [{ field: "path", operator: "begins_with", value: "/pw-ja4-bind" }],
    });
    expect(create.status).toBe(201);
    ruleId = create.data.id;
    expect(create.data.challenge_bind_ja4).toBe(true);

    // Verify persisted.
    const get1 = await apiGet(`/api/rules/${ruleId}`);
    expect(get1.data.challenge_bind_ja4).toBe(true);

    // Update to false.
    const update = await apiPut(`/api/rules/${ruleId}`, {
      challenge_bind_ja4: false,
    });
    expect(update.status).toBe(200);
    expect(update.data.challenge_bind_ja4).toBe(false);

    // Verify the change persisted.
    const get2 = await apiGet(`/api/rules/${ruleId}`);
    expect(get2.data.challenge_bind_ja4).toBe(false);
  });
});
