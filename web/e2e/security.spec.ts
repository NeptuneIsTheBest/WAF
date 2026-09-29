import { test, expect } from "@playwright/test";
import type { BrowserContext, Page } from "@playwright/test";
import { defaultSite } from "../src/types";
import type { Draft, Session, Site } from "../src/types";

async function login(context: BrowserContext) {
  const response = await context.request.post("/api/v1/auth/login", {
    headers: { Origin: "http://admin.localhost:18080" },
    data: { username: "admin", password: "browser-test-password", code: "" },
  });
  expect(response.ok()).toBeTruthy();
  const session: Session = await response.json();
  return {
    session,
    headers: {
      Origin: "http://admin.localhost:18080",
      "X-CSRF-Token": session.csrf_token,
    },
  };
}
async function addSite(context: BrowserContext, site: Site) {
  const { headers } = await login(context);
  const draft: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  draft.bundle.sites = [
    ...draft.bundle.sites.filter((s) => s.id !== site.id),
    site,
  ];
  const saved = await context.request.put("/api/v1/config/draft", {
    headers,
    data: draft,
  });
  expect(saved.ok()).toBeTruthy();
  const next: Draft = await saved.json();
  const published = await context.request.post("/api/v1/config/publish", {
    headers,
    data: { version: next.version, base_revision: next.base_revision },
  });
  expect(published.ok()).toBeTruthy();
}
function newSite(id: string): Site {
  return {
    ...defaultSite(),
    id,
    name: id,
    domains: [id + ".localhost"],
    https: false,
    redirect_http: false,
    upstreams: [{ url: "http://127.0.0.1:18081", weight: 1, health_path: "" }],
  };
}
async function selectSite(page: Page, name: string) {
  await page.getByRole("combobox", { name: "选择站点" }).click();
  await page.getByTitle(name, { exact: true }).click();
}

test("unified rules page edits all actions, rates and managed settings, preserves site isolation and read-only access", async ({
  page,
  context,
}) => {
  const first = newSite("security-editor");
  const second = newSite("security-other");
  await addSite(context, first);
  await addSite(context, second);
  const { session } = await login(context);
  await page.goto("/");
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  await selectSite(page, first.name);
  await expect(page.getByRole("combobox", { name: "选择站点" })).toHaveCount(1);
  for (const name of ["自定义规则", "速率限制规则", "托管规则"])
    await expect(page.getByRole("region", { name, exact: true })).toBeVisible();
  for (const name of ["自定义规则", "请求限流", "托管规则", "Bot 与浏览器挑战"])
    await expect(page.getByRole("menuitem", { name, exact: true })).toHaveCount(
      0,
    );
  const actions = [
    "Managed Challenge",
    "Non-Interactive Challenge",
    "Interactive Challenge",
    "Log",
    "Skip",
    "Block",
  ];
  for (const [i, action] of actions.entries()) {
    await page.getByRole("button", { name: "添加自定义规则" }).click();
    const dialog = page.getByRole("dialog", {
      name: "自定义规则",
      exact: true,
    });
    await dialog.getByLabel("规则标识", { exact: true }).fill("rule-" + i);
    await dialog.getByLabel("显示名称", { exact: true }).fill(action);
    await dialog.getByLabel("CEL 表达式", { exact: true }).fill("false");
    await dialog.getByLabel("动作", { exact: true }).click();
    await page
      .locator(".ant-select-item-option")
      .filter({ hasText: new RegExp("^" + action + " ·") })
      .click();
    if (action.includes("Challenge")) {
      await dialog.getByText("质询高级设置", { exact: true }).click();
      await dialog.getByLabel("计算强度", { exact: true }).fill("1000");
      await dialog
        .getByLabel("通行有效期（秒）", { exact: true })
        .fill(String(60 + i * 60));
    } else if (action === "Skip") {
      await dialog.getByLabel("跳过哪些检查", { exact: true }).click();
      await page
        .locator(".ant-select-item-option")
        .filter({ hasText: "全部速率限制规则" })
        .click();
      await page.keyboard.press("Escape");
    }
    await dialog.getByRole("button", { name: "保存到草稿" }).click();
    await expect(dialog).toBeHidden();
  }
  await page.getByRole("button", { name: "添加速率限制规则" }).click();
  const rate = page.getByRole("dialog", { name: "速率限制规则", exact: true });
  await rate.getByLabel("策略标识", { exact: true }).fill("api-rate");
  await rate.getByRole("button", { name: "保存到草稿" }).click();
  await page.getByRole("button", { name: "配置托管规则" }).click();
  const managed = page.getByRole("dialog", { name: "配置托管规则" });
  await managed.getByText("拦截", { exact: true }).click();
  await expect(managed.getByText("规则目录", { exact: true })).toBeVisible();
  await managed.getByRole("button", { name: "关闭", exact: true }).click();
  await page.getByRole("button", { name: "保存草稿", exact: true }).click();
  await expect(
    page.getByText("草稿已保存，尚未发布", { exact: true }),
  ).toBeVisible();
  const saved: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  const edited = saved.bundle.sites.find((s) => s.id === first.id)!;
  expect(edited.rules.map((r) => r.action)).toEqual([
    "managed_challenge",
    "non_interactive_challenge",
    "interactive_challenge",
    "log",
    "skip",
    "block",
  ]);
  expect(
    edited.rules.slice(0, 3).map((r) => r.challenge?.clearance_seconds),
  ).toEqual([60, 120, 180]);
  expect(edited.rules.slice(3).every((r) => !r.challenge)).toBeTruthy();
  expect(edited.rate_limits[0].id).toBe("api-rate");
  expect(edited.managed.mode).toBe("block");
  expect(saved.bundle.sites.find((s) => s.id === second.id)?.rules).toEqual([]);
  await page.getByRole("button", { name: "发布配置", exact: true }).click();
  await page.getByRole("button", { name: "校验并发布", exact: true }).click();
  await expect(
    page.getByText(`基于配置 v${saved.base_revision + 1} ·`, { exact: false }),
  ).toBeVisible();
  await selectSite(page, second.name);
  await expect(
    page
      .getByRole("region", { name: "自定义规则", exact: true })
      .getByText("rule-0", { exact: true }),
  ).toHaveCount(0);
  await selectSite(page, first.name);
  await expect(page.locator(".ant-message-notice")).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect
    .poll(() =>
      page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    )
    .toBeTruthy();
  await page.screenshot({
    path: "test-results/security-rules-mobile.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "test-results/security-rules.png",
    fullPage: true,
  });
  await page.route("**/api/v1/auth/session", (route) =>
    route.fulfill({
      json: { ...session, user: { ...session.user, role: "viewer" } },
    }),
  );
  await page.reload();
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "添加自定义规则" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "添加速率限制规则" }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "配置托管规则" }).click();
  await expect(
    page
      .getByRole("dialog", { name: "配置托管规则" })
      .getByRole("radio")
      .first(),
  ).toBeDisabled();
});

test("ALTCHA runs locally, requires interactive clicks, escalates managed failures and never replays APIs", async ({
  page,
  context,
}) => {
  test.setTimeout(120000);
  const site = newSite("security-flow");
  site.rules = [
    "non_interactive_challenge",
    "interactive_challenge",
    "managed_challenge",
  ].map((action, i) => ({
    id: "flow-" + i,
    name: action,
    enabled: true,
    priority: i,
    expression: `request.path == "/${["automatic", "interactive", "managed"][i]}"`,
    action: action as Site["rules"][number]["action"],
    skip: [],
    challenge: { work_factor: 1000, clearance_seconds: 60 },
  }));
  site.rate_limits = [
    {
      id: "after-clearance",
      name: "After clearance",
      enabled: true,
      expression: 'request.path == "/automatic"',
      key: "ip",
      requests_per_second: 0.001,
      burst: 1,
      ban_seconds: 0,
    },
  ];
  await addSite(context, site);
  const failures: string[] = [];
  const external: string[] = [];
  page.on("pageerror", (e) => failures.push(e.message));
  page.on("request", (r) => {
    if (!r.url().startsWith("http://security-flow.localhost:18080/"))
      external.push(r.url());
  });
  page.on("console", (message) => {
    if (
      message.text().includes("Content Security Policy") ||
      message.text().includes("violates the following")
    )
      failures.push(message.text());
  });
  await page.goto("http://security-flow.localhost:18080/automatic");
  await expect(page.locator("body")).toContainText("origin ok", {
    timeout: 30000,
  });
  const limited = await page.reload();
  expect(limited?.status()).toBe(429);
  let puzzles = 0;
  page.on("request", (r) => {
    if (r.url().includes("/.waf/challenge/puzzle?")) puzzles++;
  });
  await page.goto("http://security-flow.localhost:18080/interactive");
  const checkbox = page.locator("altcha-widget").getByRole("checkbox");
  await expect(checkbox).toBeVisible();
  await page.waitForTimeout(500);
  expect(puzzles).toBe(0);
  await page.screenshot({
    path: "test-results/interactive-challenge.png",
    fullPage: true,
  });
  await page
    .locator("altcha-widget")
    .getByText("我不是机器人", { exact: true })
    .click();
  await expect(page.locator("body")).toContainText("origin ok", {
    timeout: 30000,
  });
  const userAgent = await page.evaluate(() => navigator.userAgent);
  const headers = {
    Host: "security-flow.localhost:18080",
    "User-Agent": userAgent,
    Origin: "http://security-flow.localhost:18080",
  };
  for (let i = 0; i < 3; i++) {
    const response = await context.request.get(
      "http://127.0.0.1:18080/managed",
      { headers },
    );
    const challenge = await response.json();
    expect(challenge.challenge_mode).toBe("non_interactive");
    const token = new URL(
      challenge.challenge_url,
      "http://security-flow.localhost:18080",
    ).searchParams.get("ticket");
    const invalid = await context.request.post(
      "http://127.0.0.1:18080/.waf/challenge/solve",
      { headers, data: { ticket: token, payload: btoa("{}") } },
    );
    expect(invalid.status()).toBe(403);
  }
  await page.goto("http://security-flow.localhost:18080/managed");
  await expect(page.locator("#challenge")).toHaveAttribute(
    "data-mode",
    "interactive",
  );
  await checkbox.focus();
  await page.keyboard.press("Space");
  await expect(page.locator("body")).toContainText("origin ok", {
    timeout: 30000,
  });
  await context.clearCookies();
  const response = await context.request.post(
    "http://127.0.0.1:18080/interactive",
    { headers, data: "side-effect" },
  );
  expect(response.status()).toBe(403);
  const apiChallenge = await response.json();
  let nonVerificationPosts = 0;
  page.on("request", (r) => {
    if (r.method() === "POST" && !r.url().endsWith("/.waf/challenge/solve"))
      nonVerificationPosts++;
  });
  await page.goto(
    "http://security-flow.localhost:18080" + apiChallenge.challenge_url,
  );
  await page
    .locator("altcha-widget")
    .getByText("我不是机器人", { exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("请返回应用重试原请求", {
    timeout: 30000,
  });
  expect(new URL(page.url()).pathname).toBe("/.waf/challenge");
  expect(nonVerificationPosts).toBe(0);
  expect(external).toEqual([]);
  expect(failures).toEqual([]);
});
