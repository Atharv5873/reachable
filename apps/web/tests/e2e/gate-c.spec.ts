import { devices, expect, type Page, test } from "@playwright/test";

// S10 Gate C: the whole demo against the deployed stack, one test per step so
// each passes or fails on its own. Run it against the live site:
//   E2E_BASE_URL=https://reachable-web-sand.vercel.app npx playwright test gate-c
// Twice: at the desktop size the UI is built for, and emulating a phone.
// Everything is replay mode: no model is called (the Q&A uses the rules).

const SHOTS = process.env.GATE_C_SHOTS ?? "test-results/gate-c";
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const { defaultBrowserType, ...phone } = devices["Pixel 7"];

const shot = (page: Page, name: string) => page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });

for (const [label, use] of [
  ["desktop", {}],
  ["phone", phone],
] as const) {
  test.describe(`Gate C (${label})`, () => {
    test.use(use);

    test("1 findings re-ranked: the low-CVSS finding on a path is #1, with its target's tier", async ({ page }) => {
      await page.goto("/findings?org=org_a&scan=v1");
      const low = page.getByTestId("headline-low");
      await expect(low).toContainText("#1");
      await expect(low.getByTestId("tier-badge")).toBeVisible();
      // "Low" is relative: Reachable's #1 has a lower CVSS than the scanner's
      // unreachable top pick (S9 data: CVSS 7.5 at scanner rank ~4,000, vs a 9.8).
      const cvss = async (side: string) =>
        Number(await page.getByTestId(`headline-${side}`).locator("p.text-\\[40px\\]").last().textContent());
      expect(await cvss("low")).toBeLessThan(await cvss("high"));
      await expect(page.getByTestId("finding-row").first()).toHaveAttribute("data-status", "reachable");
      await shot(page, `${label}-1-findings`);
    });

    test("2 attack path renders; an edge opens its evidence", async ({ page }) => {
      await page.goto("/findings?org=org_a&scan=v1");
      await page.getByTestId("headline-low").click();
      await page.getByTestId("view-path").click();
      await expect(page.getByTestId("attack-graph")).toHaveAttribute("data-ready", "1");
      await page.getByTestId("path-item").first().getByRole("button").first().click();
      await expect(page.getByTestId("why-step")).toBeVisible();
      await shot(page, `${label}-2-path-evidence`);
    });

    test("3 min cut: fewest / cheapest toggle; simulate flips every crown jewel to SAFE", async ({ page }) => {
      await page.goto("/fixes?org=org_a&scan=v1");
      const graph = page.getByTestId("fix-graph");
      await expect(graph).toHaveAttribute("data-ready", "1");
      const modes = page.getByTestId("cut-mode").getByRole("radio");
      await modes.first().click();
      await expect(graph).toHaveAttribute("data-cut", "fewest");
      await modes.last().click();
      await expect(graph).toHaveAttribute("data-cut", "cheapest");
      await expect(page.getByTestId("fix-card").first()).toBeVisible();
      await page.getByTestId("simulate-button").click();
      await expect(page.getByTestId("simulate-summary")).toContainText("unreachable");
      for (const c of await page.getByTestId("crown-status").all()) await expect(c).toHaveAttribute("data-state", "safe");
      await shot(page, `${label}-3-fix-simulate`);
    });

    test("4 replay feed plays the recorded run (no model)", async ({ page }) => {
      await page.goto("/live?org=org_a&scan=v1");
      await page.getByRole("radio", { name: "instant" }).click();
      await page.getByTestId("replay-play").click();
      await expect(page.locator("[data-testid=feed-event][data-type=report_ready]")).toBeVisible();
      expect(await page.getByTestId("feed-event").count()).toBeGreaterThan(20);
      await shot(page, `${label}-4-replay`);
    });

    test("5 company-brain Q&A answers with its sources", async ({ page }) => {
      await page.goto("/ask?org=org_c&scan=v1");
      await page.getByTestId("suggestion").first().click();
      const answer = page.getByTestId("answer");
      await expect(answer.getByTestId("answer-text")).not.toBeEmpty();
      await expect(answer.getByTestId("resolved-by")).toContainText("rules");
      await expect(answer.getByText("The evidence, as edges in the graph")).toBeVisible();
      await shot(page, `${label}-5-ask`);
    });

    test("6 drift: the v2 new crown path and what memory recognised (06859 accepted)", async ({ page }) => {
      await page.goto("/drift?org=org_a&scan=v2");
      await expect(page.getByTestId("drift-alert")).toContainText("NEW CROWN PATH");
      const mem = page.getByTestId("memory-recognised");
      await expect(mem.getByTestId("accepted-risk").filter({ hasText: "06859" })).toBeVisible();
      await shot(page, `${label}-6-drift`);
    });

    test("7 evals: the S9 numbers", async ({ page }) => {
      await page.goto("/evals?org=org_a&scan=v1");
      await expect(page.getByTestId("eval-section").nth(2)).toBeVisible();
      await expect(page.getByText("path recall@10").first()).toBeVisible();
      await expect(page.getByTestId("ndcg-caveat")).toBeVisible();
      await shot(page, `${label}-7-evals`);
    });
  });
}
