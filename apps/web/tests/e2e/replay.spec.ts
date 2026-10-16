import { expect, test } from "@playwright/test";

// S10: on Vercel a serverless function can cut a long SSE response. Replay must
// not need the stream at all, and a live run must still finish if it is cut.

test("replay plays the recorded run with the SSE stream unavailable", async ({ page }) => {
  const streamed: string[] = [];
  await page.route("**/api/r/runs/*/stream", (r) => {
    streamed.push(r.request().url());
    return r.abort("connectionrefused");
  });
  await page.goto("/live?org=org_a&scan=v1");
  await expect(page.getByTestId("replay-controls")).toBeVisible();
  await page.getByRole("radio", { name: "instant" }).click();
  await page.getByTestId("replay-play").click();
  await expect(page.getByTestId("feed-event").first()).toBeVisible();
  // ...through to the report: /events ends with report_ready, like the stream.
  await expect(page.locator('[data-testid=feed-event][data-type=report_ready]')).toBeVisible();
  expect(streamed).toEqual([]); // replay never opened the stream
});

test("a live run whose stream is refused finishes by polling /events", async ({ page }) => {
  const run = "org_a:run:e2epolling00";
  const step = (seq: number, type: string, extra: object = {}) => ({ seq, type, agent: "triage", ts: 0, ...extra });
  const first = [step(0, "agent_entered"), step(1, "llm_called", { ms: 900, model: "stub", tokens_in: 10, tokens_out: 5 })];
  const rest = [
    step(2, "report_written", { agent: "reporter", headline: "Polled to the end" }),
    { type: "report_ready", run_id: run, status: "complete", headline: "Polled to the end", risk: "high" },
  ];
  const afters: string[] = [];
  await page.route("**/api/r/runs/*/stream", (r) => r.fulfill({ status: 504, body: "FUNCTION_INVOCATION_TIMEOUT" }));
  await page.route("**/api/r/runs/*/events*", (r) => {
    const after = new URL(r.request().url()).searchParams.get("after") ?? "";
    afters.push(after);
    const body = after === "-1" ? first : after === "1" ? rest : [];
    return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto(`/live?org=org_a&scan=v1&mode=live&run=${encodeURIComponent(run)}&watch=1`);
  await expect(page.locator('[data-testid=feed-event][data-type=report_ready]')).toContainText("Polled to the end");
  await expect(page.getByTestId("stream-state")).toHaveAttribute("data-state", "closed");
  expect(afters.slice(0, 2)).toEqual(["-1", "1"]); // asked only for what it had not seen
});
