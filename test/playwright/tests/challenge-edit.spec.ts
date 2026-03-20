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
