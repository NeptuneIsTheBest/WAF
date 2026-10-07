import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { Draft, Session } from "../src/types";
import { defaultSite, defaultSecurity } from "../src/types";

async function expectPageFits(page: Page) {
  await expect
    .poll(() =>
      page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    )
    .toBe(true);
}

test("console publishes policies, blocks traffic, records events and enforces RBAC", async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("browser-test-password");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "安全概览", exact: true }),
  ).toBeVisible();
  await page.getByRole("menuitem", { name: "站点管理" }).click();
  await page.getByRole("button", { name: "添加站点" }).click();
  const siteDialog = page.getByRole("dialog");
  await siteDialog.getByLabel("站点标识", { exact: true }).fill("browser-site");
  await siteDialog
    .getByLabel("显示名称", { exact: true })
    .fill("浏览器测试站点");
  await siteDialog.getByLabel("域名", { exact: true }).fill("site.localhost");
  await page.keyboard.press("Enter");
  await siteDialog.getByLabel("自动 HTTPS", { exact: true }).click();
  await siteDialog
    .getByLabel("上游 URL", { exact: true })
    .fill("http://127.0.0.1:18081");
  await siteDialog.getByRole("button", { name: "保存到草稿" }).click();
  await expect(page.getByText("浏览器测试站点", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "发布配置", exact: true }).click();
  await page.getByRole("button", { name: "校验并发布" }).click();
  await expect(page.getByText("基于配置 v1", { exact: false })).toBeVisible();
  const allowed = await context.request.get("http://127.0.0.1:18080/hello", {
    headers: { Host: "site.localhost" },
  });
  expect(allowed.status()).toBe(200);
  await page.getByRole("menuitem", { name: "安全规则" }).click();
  await page.getByRole("button", { name: "添加自定义规则" }).click();
  const ruleDialog = page.getByRole("dialog");
  await ruleDialog
    .getByLabel("规则标识", { exact: true })
    .fill("block-private");
  await ruleDialog.getByLabel("显示名称", { exact: true }).fill("阻止私有路径");
  await ruleDialog
    .getByLabel("CEL 表达式", { exact: true })
    .fill('request.path.startsWith("/blocked")');
  await ruleDialog.getByRole("button", { name: "保存到草稿" }).click();
  await page.getByRole("button", { name: "发布配置", exact: true }).click();
  await page.getByRole("button", { name: "校验并发布" }).click();
  await expect(page.getByText("基于配置 v2", { exact: false })).toBeVisible();
  const denied = await context.request.get("http://127.0.0.1:18080/blocked", {
    headers: { Host: "site.localhost" },
  });
  expect(denied.status()).toBe(403);
  await page.getByRole("menuitem", { name: "安全事件" }).click();
  await expect
    .poll(async () => {
      await page.getByRole("button", { name: "刷新", exact: true }).click();
      return await page.getByText("block-private", { exact: true }).count();
    })
    .toBeGreaterThan(0);
  await page.screenshot({
    path: "test-results/security-events.png",
    fullPage: true,
  });
  const csrf = await context.request.put("/api/v1/config/draft", { data: {} });
  expect(csrf.status()).toBe(403);
  await page.getByRole("menuitem", { name: "用户与权限" }).click();
  await page.getByRole("button", { name: "添加用户" }).click();
  const userDialog = page.getByRole("dialog");
  await userDialog.getByLabel("用户名", { exact: true }).fill("reader");
  await userDialog
    .getByLabel("初始密码", { exact: true })
    .fill("reader-test-password");
  await userDialog.getByRole("button", { name: "确定", exact: true }).click();
  await expect(page.getByText("保存登录验证信息")).toBeVisible();
  await page.getByRole("button", { name: "已保存", exact: true }).click();
  await page.getByRole("menuitem", { name: "安全概览" }).click();
  await expect(
    page.getByText("配置版本 2 已发布", { exact: true }),
  ).not.toBeVisible();
  await expect(page.getByText("当前配置 v2", { exact: true })).toBeVisible();
  await page.mouse.move(1000, 0);
  await page.screenshot({ path: "test-results/overview.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("button", { name: "打开导航" })).toBeVisible();
  await expect(page.locator(".sidebar")).toHaveCount(0);
  await expectPageFits(page);
  await page.screenshot({ path: "test-results/mobile.png", fullPage: true });
  const session = await (
    await context.request.get("/api/v1/auth/session")
  ).json();
  await context.request.post("/api/v1/auth/logout", {
    headers: {
      Origin: "http://admin.localhost:18080",
      "X-CSRF-Token": session.csrf_token,
    },
    data: {},
  });
  await page.reload();
  await page.getByLabel("用户名", { exact: true }).fill("reader");
  await page.getByLabel("密码", { exact: true }).fill("reader-test-password");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "安全概览", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "发布配置", exact: true }),
  ).toHaveCount(0);
  expect((await context.request.get("/api/v1/credentials")).status()).toBe(403);
  await page.getByRole("button", { name: "打开导航" }).click();
  const readerNavigation = page.getByRole("dialog", { name: "WAF 控制台" });
  await expect(readerNavigation).toBeVisible();
  await expect(
    readerNavigation.getByRole("menuitem", { name: "用户与权限" }),
  ).toHaveCount(0);
  await expect(
    readerNavigation.getByRole("menuitem", { name: "备份与运维" }),
  ).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("navigation closes on selection, escape, backdrop and desktop resize", async ({
  page,
  context,
}) => {
  const login = await context.request.post("/api/v1/auth/login", {
    headers: { Origin: "http://admin.localhost:18080" },
    data: { username: "admin", password: "browser-test-password", code: "" },
  });
  expect(login.ok()).toBeTruthy();
  const navigationSite = defaultSite();
  navigationSite.id = "navigation-site";
  navigationSite.name = "布局检查";
  await page.route("**/api/v1/config/draft", (route) =>
    route.fulfill({
      json: {
        version: 1,
        base_revision: 0,
        bundle: { sites: [navigationSite], security: defaultSecurity() },
      },
    }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const toggle = page.getByRole("button", { name: "打开导航" });
  const navigation = page.getByRole("dialog", { name: "WAF 控制台" });
  await toggle.click();
  await expect(navigation).toBeVisible();
  await navigation.getByRole("menuitem", { name: "站点管理" }).click();
  await expect(
    page.getByRole("heading", { name: "站点管理", exact: true }),
  ).toBeVisible();
  await expect(navigation).toBeHidden();
  await expectPageFits(page);

  await page.getByRole("button", { name: "添加站点" }).click();
  const siteDialog = page.getByRole("dialog", { name: "添加站点" });
  await siteDialog
    .getByLabel("显示名称", { exact: true })
    .fill("用于检查窄屏显示的较长站点名称");
  await expectPageFits(page);
  await siteDialog.getByRole("button", { name: "取消", exact: true }).click();

  await toggle.click();
  await expect(
    navigation.getByRole("menuitem", { name: "站点管理" }),
  ).toHaveClass(/ant-menu-item-selected/);
  await page.keyboard.press("Escape");
  await expect(navigation).toBeHidden();
  await expect(toggle).toBeFocused();

  await toggle.click();
  await expect(navigation).toBeVisible();
  await page
    .locator(".ant-drawer-mask")
    .click({ position: { x: 380, y: 100 } });
  await expect(navigation).toBeHidden();
  await toggle.click();
  await navigation
    .getByRole("menuitem", { name: "安全规则", exact: true })
    .click();
  await expect(navigation).toBeHidden();
  await page.getByRole("button", { name: "配置托管规则" }).click();
  await expect(page.getByText("规则目录", { exact: true })).toBeVisible();
  await page
    .getByRole("dialog", { name: "配置托管规则" })
    .getByRole("button", { name: "关闭", exact: true })
    .click();
  await expectPageFits(page);

  await toggle.click();
  await expect(navigation).toBeVisible();
  for (const width of [768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect(navigation).toBeHidden();
    await expect(toggle).toHaveCount(0);
    await expect(page.locator(".sidebar")).toBeVisible();
    await expectPageFits(page);
    await page.getByRole("menuitem", { name: "站点管理" }).click();
    await page.getByRole("button", { name: "添加站点" }).click();
    await expectPageFits(page);
    await siteDialog.getByRole("button", { name: "取消", exact: true }).click();
    await page.getByRole("menuitem", { name: "安全规则", exact: true }).click();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(toggle).toBeVisible();
  await expect(navigation).toBeHidden();
  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(navigation).toBeVisible();
  await navigation.getByRole("button", { name: "关闭导航" }).click();
  await expect(toggle).toBeFocused();
});

test("browser solves multiple challenge scopes and backup API returns encrypted data", async ({
  page,
  context,
}) => {
  const login = await context.request.post("/api/v1/auth/login", {
    headers: { Origin: "http://admin.localhost:18080" },
    data: { username: "admin", password: "browser-test-password", code: "" },
  });
  expect(login.ok()).toBeTruthy();
  const session: Session = await login.json();
  const headers = {
    Origin: "http://admin.localhost:18080",
    "X-CSRF-Token": session.csrf_token,
  };
  const draft: Draft = await (
    await context.request.get("/api/v1/config/draft")
  ).json();
  const site = defaultSite();
  site.id = "challenge-site";
  site.name = "Browser challenge";
  site.https = false;
  site.redirect_http = false;
  site.upstreams = [
    { url: "http://127.0.0.1:18081", weight: 1, health_path: "" },
  ];
  site.domains = ["challenge.localhost"];
  draft.bundle.security.managed.default.mode = "block";
  draft.bundle.security.custom_rules.push(
    ...[1, 2].map((n) => ({
      scope: { mode: "sites" as const, site_ids: [site.id] },
      id: `challenge-${n}`,
      name: `Challenge ${n}`,
      enabled: true,
      priority: n,
      expression: "true",
      action: "non_interactive_challenge" as const,
      challenge: { work_factor: 1000, clearance_seconds: 1800 },
      skip: [],
    })),
  );
  draft.bundle.sites.push(site);
  const saved = await context.request.put("/api/v1/config/draft", {
    headers,
    data: draft,
  });
  expect(saved.ok()).toBeTruthy();
  const savedDraft: Draft = await saved.json();
  const published = await context.request.post("/api/v1/config/publish", {
    headers,
    data: {
      version: savedDraft.version,
      base_revision: savedDraft.base_revision,
    },
  });
  expect(published.ok()).toBeTruthy();
  const failures: string[] = [];
  page.on("pageerror", (e) => failures.push(e.message));
  let solved = 0;
  page.on("response", (response) => {
    if (
      response.url().endsWith("/.waf/challenge/solve") &&
      response.status() === 200
    )
      solved++;
  });
  await page.goto("http://challenge.localhost:18080/protected");
  await expect(page.locator("body")).toContainText("origin ok", {
    timeout: 20000,
  });
  expect(solved).toBe(2);
  await page.reload();
  await expect(page.locator("body")).toContainText("origin ok");
  expect(solved).toBe(2);
  const attack = await page.evaluate(
    async () =>
      (await fetch("/?q=" + encodeURIComponent("<script>alert(1)</script>")))
        .status,
  );
  expect(attack).toBe(403);
  const backup = await context.request.post("/api/v1/backups", {
    headers,
    data: { password: "browser-backup-passphrase" },
  });
  expect(backup.status()).toBe(201);
  const artifact = await backup.json();
  const download = await context.request.get(
    `/api/v1/backups/${artifact.name}`,
  );
  expect(download.ok()).toBeTruthy();
  expect((await download.body()).toString("utf8", 0, 21)).toBe(
    "age-encryption.org/v1",
  );
  expect(failures).toEqual([]);
});
