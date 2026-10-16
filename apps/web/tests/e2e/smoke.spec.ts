import { expect, test } from "@playwright/test";

// The demo, in order: the re-ranked findings, the headline finding's attack
// path, the min cut, and the simulation that flips the crown jewel to safe.
// Replay mode: nothing here calls a model.
test("headline finding -> its path -> the min cut -> simulate makes the crown jewels safe", async ({ page }) => {
  await page.goto("/findings?org=org_a&scan=v1");

  // 1. Findings: two orders of the same findings, and the headline pair.
  await expect(page.getByTestId("headline-pair")).toBeVisible();
  const rows = page.getByTestId("finding-row");
  await expect(rows.first()).toHaveAttribute("data-status", "reachable");
  // S9: a reachable row names its target's sensitivity tier; org_a has two tiers.
  const tiers = page.getByTestId("findings-table").getByTestId("tier-badge");
  await expect(tiers.first()).toBeVisible();
  expect(new Set(await tiers.evaluateAll((els) => els.map((e) => e.getAttribute("data-tier")))).size).toBeGreaterThan(1);
  await page.getByTestId("order-toggle").getByRole("radio", { name: "Sorted by severity" }).click();
  await expect(page.getByTestId("findings-table")).toHaveAttribute("data-order", "severity");
  await expect(rows.first()).not.toHaveAttribute("data-status", "reachable"); // CVSS-first puts noise on top

  // Select the headline: the low-CVSS finding Reachable ranks first.
  await page.getByTestId("headline-low").click();
  await expect(page).toHaveURL(/[?&]f=/);
  const finding = new URL(page.url()).searchParams.get("f")!;
  await expect(page.locator(`[data-testid=finding-row][data-finding="${finding}"]`)).toHaveAttribute("aria-selected", "true");

  // 2. Its attack path renders (Cytoscape canvas, laid out and animated in).
  await page.getByTestId("view-path").click();
  await expect(page).toHaveURL(/\/paths\?/);
  await expect(page.getByTestId("paths-title")).toContainText("through");
  const graph = page.getByTestId("attack-graph");
  await expect(graph).toHaveAttribute("data-ready", "1");
  expect(Number(await graph.getAttribute("data-nodes"))).toBeGreaterThan(2);
  await expect(page.getByTestId("path-item").first()).toBeVisible();

  // ...and an edge's evidence opens (why_step).
  await page.getByTestId("path-item").first().getByRole("button").first().click();
  await expect(page.getByTestId("why-step")).toBeVisible();

  // 3. The min cut, with the selection kept in the URL.
  await page.getByRole("link", { name: /fewest fixes that cut/ }).click();
  await expect(page).toHaveURL(new RegExp(`/fixes\?.*f=${encodeURIComponent(finding)}`));
  await expect(page.getByTestId("fix-graph")).toHaveAttribute("data-ready", "1");
  await page.getByTestId("cut-mode").getByRole("radio").first().click(); // fewest
  await expect(page.getByTestId("fix-graph")).toHaveAttribute("data-cut", "fewest");
  await expect(page.getByTestId("fix-card").first()).toBeVisible();
  await expect(page.getByTestId("fix-card").first().getByTestId("tier-badge")).toBeVisible();
  await expect(page.getByTestId("crown-status").first().getByTestId("tier-badge")).toBeVisible();
  await expect(page.getByTestId("convergence")).toBeVisible(); // one fix, many paths

  // Simulate: every crown jewel goes from reachable to safe.
  const crowns = page.getByTestId("crown-status");
  await expect(crowns.first()).toHaveAttribute("data-state", "reachable");
  await page.getByTestId("simulate-button").click();
  await expect(page.getByTestId("simulate-summary")).toContainText("unreachable");
  for (const c of await crowns.all()) await expect(c).toHaveAttribute("data-state", "safe");
  await expect(page.getByTestId("fix-graph")).toHaveAttribute("data-severed", "1");
});

test("every screen survives the backend being down", async ({ page }) => {
  await page.route("**/api/r/**", (r) => r.fulfill({ status: 502, contentType: "application/json", body: '{"detail":"down"}' }));
  for (const p of ["/findings", "/paths", "/fixes", "/live", "/ask", "/drift", "/evals"]) {
    await page.goto(`${p}?org=org_a&scan=v1`);
    await expect(page.locator("main")).toBeVisible();
    await expect(page.getByText(/not answering|No finished run|Press Replay|Who owns it/).first()).toBeVisible();
  }
});
