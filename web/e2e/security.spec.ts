import { test, expect } from "@playwright/test";
import type { BrowserContext, Page } from "@playwright/test";
import { defaultSite, defaultSecurity } from "../src/types";
import type { Draft, Session, Site, Security, CustomRule } from "../src/types";

async function login(context: BrowserContext) {
  let response = await context.request.get("/api/v1/auth/session");
  if (!response.ok())
    response = await context.request.post("/api/v1/auth/login", {
      headers: { Origin: "http://admin.localhost:18080" },
      data: { username: "admin", password: "browser-test-password", code: "" },
    });
  expect(response.ok(), await response.text()).toBeTruthy();
  const session: Session = await response.json();
  return {
    session,
    headers: {
      Origin: "http://admin.localhost:18080",
      "X-CSRF-Token": session.csrf_token,
    },
  };
}
async function addSite(
  context: BrowserContext,
  site: Site,
  security?: Security,
) {
  const { headers } = await login(context);
  const draft: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  if (security) draft.bundle.security = security;
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

async function saveDraft(page: Page) {
  const saved = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/v1/config/draft" &&
      response.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "保存草稿", exact: true }).click();
  const response = await saved;
  expect(response.ok(), await response.text()).toBeTruthy();
  await expect(page.getByText("草稿已保存", { exact: true })).toBeVisible();
}

test("global security editor handles scopes, overrides, events and read-only access", async ({
  page,
  context,
}) => {
  const first = newSite("security-editor");
  const second = newSite("security-other");
  const probePath = "/crs-probe-" + test.info().repeatEachIndex;
  test.setTimeout(120000);
  await addSite(context, first, defaultSecurity());
  await addSite(context, second);
  const { session } = await login(context);
  await page.goto("/");
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: "选择站点", exact: true }),
  ).toHaveCount(0);
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
    await dialog
      .getByLabel("CEL 表达式", { exact: true })
      .fill(action === "Block" ? 'request.path == "/global-block"' : "false");
    if (i === 0) {
      await dialog
        .getByRole("radio", { name: "指定网站", exact: true })
        .check();
      await dialog.getByLabel("选择适用网站", { exact: true }).click();
      await page.getByTitle(first.name, { exact: true }).click();
      await page.keyboard.press("Escape");
      await dialog.getByLabel("CEL 表达式", { exact: true }).fill("true");
      await dialog
        .getByLabel("样例请求", { exact: true })
        .fill(JSON.stringify({ site: { id: second.id } }));
      await dialog.getByRole("button", { name: "校验并运行样例" }).click();
      await expect(
        page.getByText("规则有效，样例请求不匹配", { exact: true }),
      ).toBeVisible();
      await dialog
        .getByLabel("样例请求", { exact: true })
        .fill(JSON.stringify({ site: { id: first.id } }));
      await dialog.getByRole("button", { name: "校验并运行样例" }).click();
      await expect(
        page.getByText("规则有效，样例请求匹配", { exact: true }),
      ).toBeVisible();
      await dialog.getByLabel("CEL 表达式", { exact: true }).fill("false");
    }
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
  await rate
    .getByLabel("CEL 表达式", { exact: true })
    .fill('request.path == "/limited"');
  await rate.getByRole("button", { name: "保存到草稿" }).click();
  await page.getByRole("button", { name: "配置托管规则" }).click();
  const managed = page.getByRole("dialog", { name: "配置托管规则" });
  await managed.getByText("拦截", { exact: true }).click();
  await expect(managed.getByText("规则目录", { exact: true })).toBeVisible();
  await managed.getByRole("button", { name: "关闭", exact: true }).click();
  await saveDraft(page);
  const saved: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  const edited = saved.bundle.security;
  expect(edited.custom_rules.map((r) => r.action)).toEqual([
    "managed_challenge",
    "non_interactive_challenge",
    "interactive_challenge",
    "log",
    "skip",
    "block",
  ]);
  expect(
    edited.custom_rules.slice(0, 3).map((r) => r.challenge?.clearance_seconds),
  ).toEqual([60, 120, 180]);
  expect(edited.custom_rules.slice(3).every((r) => !r.challenge)).toBeTruthy();
  expect(edited.rate_limits[0].id).toBe("api-rate");
  expect(edited.managed.default.mode).toBe("block");
  expect(edited.custom_rules[0].scope).toEqual({
    mode: "sites",
    site_ids: [first.id],
  });
  expect(edited.custom_rules[5].scope.mode).toBe("all");
  expect(saved.bundle.sites.find((s) => s.id === first.id)).not.toHaveProperty(
    "rules",
  );
  await page.getByRole("button", { name: "发布配置", exact: true }).click();
  await page.getByRole("button", { name: "校验并发布", exact: true }).click();
  await expect(
    page.getByText(`基于配置 v${saved.base_revision + 1} ·`, { exact: false }),
  ).toBeVisible();
  // A site edit must keep the global security configuration.
  await page.getByRole("menuitem", { name: "站点管理", exact: true }).click();
  const row = page.getByRole("row").filter({ hasText: first.name }).first();
  await row.getByRole("button", { name: "编辑", exact: true }).click();
  const siteEditor = page.getByRole("dialog");
  await siteEditor.getByLabel("显示名称", { exact: true }).fill("编辑后的网站");
  await siteEditor.getByRole("button", { name: "保存到草稿" }).click();
  await saveDraft(page);
  const afterSite: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  expect(afterSite.bundle.security).toEqual(saved.bundle.security);
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  await page.getByRole("button", { name: "添加覆盖策略" }).click();
  const override = page.getByRole("dialog", {
    name: "托管覆盖策略",
    exact: true,
  });
  await override.getByLabel("策略标识", { exact: true }).fill("observe-path");
  await override
    .getByLabel("CEL 表达式", { exact: true })
    .fill('request.path == "/observe"');
  await override.getByRole("radio", { name: "指定网站", exact: true }).check();
  await override.getByLabel("选择适用网站", { exact: true }).click();
  await page.getByTitle("编辑后的网站", { exact: true }).click();
  await page.keyboard.press("Escape");
  await override.getByRole("button", { name: "保存到草稿" }).click();
  const policy = page.getByRole("dialog", {
    name: "配置托管覆盖 · observe-path",
  });
  await policy.getByRole("radio", { name: "观察", exact: true }).check();
  await policy.getByRole("button", { name: "关闭", exact: true }).click();
  await page.getByRole("button", { name: "发布配置", exact: true }).click();
  await page.getByRole("button", { name: "校验并发布", exact: true }).click();
  await expect(
    page.getByText(`基于配置 v${saved.base_revision + 2} ·`, { exact: false }),
  ).toBeVisible();
  const attack = "?q=" + encodeURIComponent("<script>alert(1)</script>");
  for (const [site, path, status] of [
    [first, "/observe" + attack, 200],
    [second, "/observe" + attack, 403],
    [first, "/global-block", 403],
    [second, "/global-block", 403],
  ] as const) {
    expect(
      (
        await context.request.get("http://127.0.0.1:18080" + path, {
          headers: { Host: site.domains[0] },
        })
      ).status(),
    ).toBe(status);
  }
  const third = newSite("security-new");
  await addSite(context, third);
  expect(
    (
      await context.request.get("http://127.0.0.1:18080/global-block", {
        headers: { Host: third.domains[0] },
      })
    ).status(),
  ).toBe(403);
  await page.reload();
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  expect(
    (
      await context.request.get("http://127.0.0.1:18080" + probePath, {
        headers: { Host: first.domains[0], "User-Agent": "sqlmap" },
      })
    ).status(),
  ).toBe(403);
  await page.getByRole("menuitem", { name: "安全事件", exact: true }).click();
  const eventRow = page
    .getByRole("row")
    .filter({ has: page.getByText(probePath, { exact: true }) })
    .filter({ has: page.getByText(first.id, { exact: true }) })
    .first();
  await expect
    .poll(async () => {
      await page.getByRole("button", { name: "刷新", exact: true }).click();
      return eventRow.count();
    })
    .toBeGreaterThan(0);
  await eventRow.getByRole("button", { name: "查看", exact: true }).click();
  await page
    .getByRole("dialog", { name: "事件详情" })
    .getByRole("button", { name: "添加规则例外" })
    .click();
  const exceptionDialog = page
    .getByRole("dialog")
    .filter({ hasText: "检查例外范围后再发布" });
  await exceptionDialog
    .getByLabel("参数限定", { exact: true })
    .fill("REQUEST_HEADERS:User-Agent");
  await exceptionDialog.getByRole("button", { name: "加入草稿" }).click();
  const exceptionPolicy = page.getByRole("dialog", {
    name: "配置托管规则",
    exact: true,
  });
  await expect(exceptionPolicy).toBeVisible();
  await exceptionPolicy
    .getByRole("button", { name: "关闭", exact: true })
    .click();
  await saveDraft(page);
  const withException: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  expect(
    withException.bundle.security.managed.default.exclusions[0],
  ).toMatchObject({
    scope: { mode: "sites", site_ids: [first.id] },
    path_prefix: probePath,
    target: "REQUEST_HEADERS:User-Agent",
  });
  await page.getByRole("button", { name: "发布配置", exact: true }).click();
  await page.getByRole("button", { name: "校验并发布", exact: true }).click();
  await expect(
    page.getByText(`基于配置 v${withException.base_revision + 1} ·`, {
      exact: false,
    }),
  ).toBeVisible();
  for (const [site, status] of [
    [first, 200],
    [second, 403],
  ] as const) {
    expect(
      (
        await context.request.get("http://127.0.0.1:18080" + probePath, {
          headers: { Host: site.domains[0], "User-Agent": "sqlmap" },
        })
      ).status(),
    ).toBe(status);
  }
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
  const security = defaultSecurity();
  security.custom_rules = [
    "non_interactive_challenge",
    "interactive_challenge",
    "managed_challenge",
  ].map((action, i) => ({
    scope: { mode: "sites", site_ids: [site.id] },
    id: "flow-" + i,
    name: action,
    enabled: true,
    priority: i,
    expression: `request.path == "/${["automatic", "interactive", "managed"][i]}"`,
    action: action as CustomRule["action"],
    skip: [],
    challenge: { work_factor: 1000, clearance_seconds: 60 },
  }));
  security.rate_limits = [
    {
      scope: { mode: "sites", site_ids: [site.id] },
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
  await addSite(context, site, security);
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

test("global rules can be prepared before adding any websites", async ({
  page,
  context,
}) => {
  await login(context);
  let draft: Draft = {
    base_revision: 0,
    version: 1,
    bundle: { sites: [], security: defaultSecurity() },
  };
  await page.route("**/api/v1/config/draft", async (route) => {
    if (route.request().method() === "PUT") {
      draft = route.request().postDataJSON();
      draft.version++;
    }
    await route.fulfill({ json: draft });
  });
  await page.goto("/");
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  await expect(
    page.getByText("请先添加并选择一个站点", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "添加自定义规则" }).click();
  const editor = page.getByRole("dialog", { name: "自定义规则", exact: true });
  await editor.getByLabel("规则标识", { exact: true }).fill("before-sites");
  await expect(
    editor.getByRole("radio", { name: "所有网站（含新增网站）" }),
  ).toBeChecked();
  await editor.getByRole("button", { name: "保存到草稿" }).click();
  await saveDraft(page);
  expect(draft.bundle.sites).toEqual([]);
  expect(draft.bundle.security.custom_rules[0].scope).toEqual({
    mode: "all",
    site_ids: [],
  });
  await page.reload();
  await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  await expect(
    page.getByText("before-sites", { exact: true }).first(),
  ).toBeVisible();
});
