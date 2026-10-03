const { test, expect } = require("@playwright/test");

test("follow eviction, reserve, evidence, review and reset", async ({
  page,
}, testInfo) => {
  const failures = [];
  const external = [];
  page.on("pageerror", (error) => failures.push(error.message));
  page.on("request", (request) => {
    if (new URL(request.url()).hostname !== "127.0.0.1")
      external.push(request.url());
  });
  await page.goto("/");
  const critical = () => page.getByRole("button", { name: /^A-017,/ });
  await expect(critical()).toContainText("IN CONTEXT");
  await page
    .getByRole("button", { name: "Advance the shift", exact: true })
    .click();
  await expect(critical()).toContainText("OUTSIDE");
  await page
    .getByRole("button", { name: "Severity reserve", exact: true })
    .click();
  await expect(critical()).toContainText("IN CONTEXT");
  await page.getByRole("button", { name: /^A-018,/ }).click();
  await expect(page.locator("#detail")).toContainText(
    "Displaced by the reserve",
  );
  await page.getByText("Raw synthetic record", { exact: true }).click();
  await expect(page.locator("#raw")).toBeVisible();
  await expect(page.locator("#raw")).toContainText(
    "kibana.alert.rule.parameters.severity",
  );
  await page
    .getByRole("button", { name: "Keep sample verdict", exact: true })
    .click();
  await expect(page.locator("#decision")).toHaveText(
    "Sample verdict kept in this page.",
  );
  await page.getByRole("button", { name: "Discard", exact: true }).click();
  await expect(page.locator("#verdict")).toBeEmpty();
  await page.getByRole("button", { name: "Reset case", exact: true }).click();
  await expect(page.locator("#decision")).toHaveText("Awaiting your review");
  await expect(page.locator("#position")).toHaveText("3 / 6 alerts arrived");
  await expect(
    page.getByRole("button", { name: "Recency only", exact: true }),
  ).toBeFocused();
  await page
    .getByRole("button", { name: "Recency only", exact: true })
    .press("Tab");
  await expect(
    page.getByRole("button", { name: "Severity reserve", exact: true }),
  ).toBeFocused();
  await page
    .getByRole("button", { name: "Severity reserve", exact: true })
    .press("Enter");
  await expect(
    page.getByRole("button", { name: "Severity reserve", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page
    .getByRole("button", { name: "Advance the shift", exact: true })
    .click();
  await critical().click();
  await expect(page.locator("#detail")).toContainText(
    "Included from the severity reserve",
  );
  const bounds = await page.evaluate(() => ({
    width: innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(bounds.content).toBeLessThanOrEqual(bounds.width);
  expect(failures).toEqual([]);
  expect(external).toEqual([]);
  await page.screenshot({
    path: testInfo.outputPath("workbench.png"),
    fullPage: true,
  });
});

test("failed load is explicit and retry recovers", async ({ page }) => {
  await page.route("**/api/case", (route) =>
    route.fulfill({ status: 500, body: "Fixture unavailable" }),
  );
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText("Check the terminal");
  await expect(page.locator("#case")).toBeHidden();
  await page.unroute("**/api/case");
  await page.getByRole("button", { name: "Retry loading case" }).click();
  await expect(page.locator("#case")).toBeVisible();
  await expect(page.getByRole("alert")).toBeHidden();
});
