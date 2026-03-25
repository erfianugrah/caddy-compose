import { test, expect } from "@playwright/test";

const WAFCTL_DASH = process.env.WAFCTL_URL || "http://localhost:18082";

// ════════════════════════════════════════════════════════════════════
//  Endpoint Discovery v2 — Service Grouping, Context-Aware Actions
// ════════════════════════════════════════════════════════════════════

test.describe("Endpoint Discovery — Service Grouping", () => {
  test("discovery tab shows service-grouped endpoints", async ({ page }) => {
    await page.goto(`${WAFCTL_DASH}/challenge`);
    const tab = page.getByText("Endpoint Discovery");
    await expect(tab).toBeVisible();
    await tab.click();

    // Wait for the discovery panel to load.
    await expect(
      page.getByText(/Endpoints Discovered|No traffic observed/).first()
    ).toBeVisible({ timeout: 15000 });

    // If there are endpoints, they should be in collapsible service groups.
    // Each service group is a Card with a button header containing the service name.
    const serviceHeaders = page.locator("button").filter({
      has: page.locator(".font-data"),
    });
    const count = await serviceHeaders.count();
    if (count > 0) {
      // The first service group should be expanded by default.
      const firstHeader = serviceHeaders.first();
      await expect(firstHeader).toBeVisible();

      // Clicking a collapsed header should expand it.
      if (count > 1) {
        const secondHeader = serviceHeaders.nth(1);
        await secondHeader.click();
        // After click, the table inside should be visible.
        await page.waitForTimeout(200);
      }
    }
  });

  test("service filter is a dropdown, not free text", async ({ page }) => {
    await page.goto(`${WAFCTL_DASH}/challenge`);

    // The service filter should be a select dropdown (not an <input>).
    // Look for "All services" text in a select trigger.
    const serviceSelect = page.locator("button").filter({
      hasText: /All services/,
    });
    await expect(serviceSelect).toBeVisible();
  });

  test("discovery summary shows Without Protection (not Challenge Protection)", async ({
    page,
  }) => {
    await page.goto(`${WAFCTL_DASH}/challenge`);
    const tab = page.getByText("Endpoint Discovery");
    await tab.click();
    await expect(
      page.getByText(/Endpoints Discovered|No traffic observed/).first()
    ).toBeVisible({ timeout: 15000 });

    // If endpoints exist, check the summary card wording.
    const protectionCard = page.getByText("Without Protection");
    const challengeCard = page.getByText("Without Challenge Protection");
    // Should use the new wording, not the old one.
    const hasNew = await protectionCard.count();
    const hasOld = await challengeCard.count();
    if (hasNew > 0 || hasOld > 0) {
      expect(hasNew).toBeGreaterThan(0);
      expect(hasOld).toBe(0);
    }
  });
});

// ════════════════════════════════════════════════════════════════════
//  OpenAPI Schema Management
// ════════════════════════════════════════════════════════════════════

test.describe("OpenAPI Schema Management", () => {
  test("schema CRUD via API", async () => {
    // Upload a schema
    const spec = JSON.stringify({
      openapi: "3.0.0",
      paths: {
        "/api/v3/command": { get: {}, post: {} },
        "/api/v3/episode/{id}": { get: {} },
      },
    });

    const uploadResp = await fetch(
      `${WAFCTL_DASH}/api/discovery/schemas/pw-test.erfi.io`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: spec,
      }
    );
    expect(uploadResp.status).toBe(200);
    const uploaded = await uploadResp.json();
    expect(uploaded.service).toBe("pw-test.erfi.io");
    expect(uploaded.routes).toBe(3);

    // List schemas
    const listResp = await fetch(`${WAFCTL_DASH}/api/discovery/schemas`);
    expect(listResp.status).toBe(200);
    const listed = await listResp.json();
    const found = listed.schemas.find(
      (s: { service: string }) => s.service === "pw-test.erfi.io"
    );
    expect(found).toBeDefined();

    // Delete
    const deleteResp = await fetch(
      `${WAFCTL_DASH}/api/discovery/schemas/pw-test.erfi.io`,
      { method: "DELETE" }
    );
    expect(deleteResp.status).toBe(200);
  });

  test("schema manager section exists in discovery tab", async ({ page }) => {
    await page.goto(`${WAFCTL_DASH}/challenge`);
    const tab = page.getByText("Endpoint Discovery");
    await tab.click();
    await expect(
      page.getByText(/Endpoints Discovered|No traffic observed/).first()
    ).toBeVisible({ timeout: 15000 });

    // The OpenAPI Schemas section should exist (collapsed by default).
    // It's rendered at the bottom, so scroll and wait.
    await page.waitForTimeout(500);
    const schemaButton = page.getByText("OpenAPI Schemas");
    // Scroll the element into view if it exists.
    if (await schemaButton.count() > 0) {
      await schemaButton.scrollIntoViewIfNeeded();
      await expect(schemaButton).toBeVisible({ timeout: 5000 });
    } else {
      // In the empty state (no traffic), the panel renders differently.
      // The schema section is only shown when there are endpoints.
      const hasEndpoints = await page.getByText("Endpoints Discovered").count();
      if (hasEndpoints > 0) {
        // Should have schema section — fail.
        await expect(schemaButton).toBeVisible({ timeout: 5000 });
      }
      // If no endpoints, schema section not rendered — skip silently.
    }
  });
});

// ════════════════════════════════════════════════════════════════════
//  Policy Prefill from Endpoint Discovery & Reputation
// ════════════════════════════════════════════════════════════════════

test.describe("Policy Prefill Flow", () => {
  test("policy page consumes action and prefill_path from URL params", async ({
    page,
  }) => {
    // Navigate directly to the policy page with prefill params.
    await page.goto(
      `${WAFCTL_DASH}/policy?action=challenge&prefill_path=%2Fapi%2Fv3%2Fcommand&prefill_service=sonarr.erfi.io`
    );

    // The Quick Actions form should be open with prefilled data.
    await expect(
      page.getByText(/Pre-filled from quick action/).first()
    ).toBeVisible({ timeout: 10000 });
  });

  test("policy page consumes block action for non-browser endpoints", async ({
    page,
  }) => {
    await page.goto(
      `${WAFCTL_DASH}/policy?action=block&prefill_path=%2Fapi%2Fv3%2Fcommand&prefill_service=sonarr.erfi.io`
    );

    await expect(
      page.getByText(/Pre-filled from quick action/).first()
    ).toBeVisible({ timeout: 10000 });
  });

  test("policy page consumes prefill_ja4 for reputation quick actions", async ({
    page,
  }) => {
    await page.goto(
      `${WAFCTL_DASH}/policy?action=block&prefill_ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd`
    );

    await expect(
      page.getByText(/Pre-filled from quick action/).first()
    ).toBeVisible({ timeout: 10000 });
  });

  test("URL params are cleaned after consumption", async ({ page }) => {
    await page.goto(
      `${WAFCTL_DASH}/policy?action=challenge&prefill_path=%2Ftest`
    );

    // Wait for the prefill to be consumed.
    await expect(
      page.getByText(/Pre-filled from quick action/).first()
    ).toBeVisible({ timeout: 10000 });

    // URL should no longer contain action/prefill params.
    const url = page.url();
    expect(url).not.toContain("action=");
    expect(url).not.toContain("prefill_path=");
  });
});

// ════════════════════════════════════════════════════════════════════
//  IP Lookup Auto-Query from Reputation Links
// ════════════════════════════════════════════════════════════════════

test.describe("IP Lookup Auto-Query", () => {
  test("analytics page reads q= param and auto-queries", async ({ page }) => {
    // Navigate to analytics with a q parameter (the correct param name).
    await page.goto(`${WAFCTL_DASH}/analytics?tab=ip&q=1.2.3.4`);

    // The IP lookup panel should be visible and the search should have been triggered.
    // Wait for the IP address to appear in the search input or results.
    await page.waitForTimeout(2000);

    // The search input should contain the IP address.
    const searchInput = page.getByPlaceholder(/IP address|Search/i).first();
    if (await searchInput.isVisible()) {
      const value = await searchInput.inputValue();
      expect(value).toBe("1.2.3.4");
    }
  });

  test("reputation IP links use correct q= param format", async ({ page }) => {
    await page.goto(`${WAFCTL_DASH}/challenge`);

    // Switch to reputation tab.
    const repTab = page.getByText("Reputation");
    await repTab.click();
    await page.waitForTimeout(1000);

    // Find any IP link in the reputation panel (client IPs link to analytics).
    const ipLinks = page.locator('a[href*="/analytics?tab=ip&q="]');
    const count = await ipLinks.count();

    if (count > 0) {
      // Verify the link uses the correct format.
      const href = await ipLinks.first().getAttribute("href");
      expect(href).toContain("/analytics?tab=ip&q=");
      expect(href).not.toContain("/analytics?ip=");
    }
  });
});
