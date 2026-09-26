import { test, expect } from "@playwright/test";
import type { Draft, Session } from "../src/types";
import { defaultSite } from "../src/types";

test("console publishes policies, blocks traffic, records events and enforces RBAC", async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("browser-test-password");
  await page.getByRole("button", { name: "安全登录" }).click();
  await expect(page.getByText("流量安全，一目了然")).toBeVisible();
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
  await page.getByRole("menuitem", { name: "自定义规则" }).click();
  await page.getByRole("button", { name: "添加规则" }).click();
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
  await expect(page.getByText("保存双因素认证资料")).toBeVisible();
  await page.getByRole("button", { name: "已安全保存" }).click();
  await page.getByRole("menuitem", { name: "安全概览" }).click();
  await page.screenshot({ path: "test-results/overview.png", fullPage: true });
  await page.setViewportSize({ width: 420, height: 900 });
  await expect(page.locator(".sidebar")).toHaveCSS("width", "80px");
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
  await page.getByRole("button", { name: "安全登录" }).click();
  await expect(page.getByText("流量安全，一目了然")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "发布配置", exact: true }),
  ).toHaveCount(0);
  expect((await context.request.get("/api/v1/credentials")).status()).toBe(403);
  expect(errors).toEqual([]);
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
  site.managed.mode = "block";
  site.bot.difficulty = 8;
  site.routes.forEach((r) => (r.allow_challenge = true));
  site.rules = [1, 2].map((n) => ({
    id: `challenge-${n}`,
    name: `Challenge ${n}`,
    enabled: true,
    priority: n,
    expression: "true",
    action: "challenge" as const,
    skip: [],
  }));
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
