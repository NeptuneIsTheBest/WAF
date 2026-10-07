import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Alert,
  App as AntApp,
  Avatar,
  Button,
  ConfigProvider,
  Drawer,
  Dropdown,
  Form,
  Grid,
  Input,
  Layout,
  Menu,
  Modal,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  ApiOutlined,
  AuditOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  HistoryOutlined,
  KeyOutlined,
  LogoutOutlined,
  MenuOutlined,
  SaveOutlined,
  SecurityScanOutlined,
  SendOutlined,
  TeamOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { api, setCSRF } from "./api";
import { normalizeBundle, defaultBundle, defaultSecurity } from "./types";
import type {
  Draft,
  Revision,
  SecurityEvent,
  Session,
  Site,
  Bundle,
  Security,
} from "./types";
import { SecurityRulesPage, RoutesPage, SitesPage } from "./PolicyPages";
import type { PolicyProps } from "./PolicyPages";
import {
  AuditPage,
  BackupsPage,
  CertificatesPage,
  EventsPage,
  OverviewPage,
  RevisionsPage,
  UsersPage,
} from "./OperationsPages";
import "./style.css";
const { Title, Text, Paragraph } = Typography;
const loginErrors: Record<string, string> = {
  invalid_credentials_or_mfa: "用户名、密码或验证码不正确",
  login_rate_limited: "登录尝试过于频繁，请稍后再试",
  login_busy: "服务繁忙，请稍后再试",
  admin_busy: "服务繁忙，请稍后再试",
  invalid_origin: "请从管理后台地址重新打开登录页",
  https_required: "请使用 HTTPS 地址登录",
  access_denied: "当前地址无法访问管理后台，请联系管理员",
};
function Login({ onLogin }: { onLogin: (s: Session) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (v: {
    username: string;
    password: string;
    code: string;
  }) => {
    setBusy(true);
    setError("");
    try {
      onLogin(
        await api<Session>("/auth/login", "POST", { ...v, code: v.code || "" }),
      );
    } catch (e) {
      setError(loginErrors[(e as Error).message] || "登录失败，请稍后重试");
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="login-page">
      <div className="login-content">
        <div className="login-brand">
          <SecurityScanOutlined aria-hidden="true" />
          <span>WAF</span>
        </div>
        <div className="login-card">
          <Title level={1}>登录控制台</Title>
          {error && (
            <Alert
              type="error"
              showIcon
              title={error}
              className="form-bottom"
            />
          )}
          <Form layout="vertical" onFinish={submit} requiredMark={false}>
            <Form.Item
              name="username"
              label="用户名"
              rules={[{ required: true, message: "请输入用户名" }]}
            >
              <Input
                size="large"
                prefix={<UserOutlined aria-hidden="true" />}
                autoComplete="username"
                placeholder="请输入用户名"
              />
            </Form.Item>
            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true, message: "请输入密码" }]}
            >
              <Input.Password size="large" autoComplete="current-password" />
            </Form.Item>
            <Form.Item
              name="code"
              label="验证码或恢复码"
              extra="填写验证器中的 6 位验证码，或使用一次性恢复码。"
            >
              <Input
                size="large"
                autoComplete="one-time-code"
                placeholder="请输入验证码或恢复码"
              />
            </Form.Item>
            <Button
              block
              size="large"
              type="primary"
              htmlType="submit"
              loading={busy}
            >
              登录
            </Button>
          </Form>
        </div>
        <p className="login-help">无法登录时请联系管理员</p>
      </div>
    </main>
  );
}
function Console() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState("overview");
  const [managedRequest, setManagedRequest] = useState<{
    id: string;
    nonce: number;
  } | null>(null);
  const [draft, setDraft] = useState<Draft>();
  const [active, setActive] = useState<Bundle>(defaultBundle());
  const [selected, setSelected] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [loadError, setLoadError] = useState("");
  const [collapsed, setCollapsed] = useState(false);
  const [navigationOpen, setNavigationOpen] = useState(false);
  const screens = Grid.useBreakpoint();
  const mobile = screens.md === false;
  useEffect(() => {
    if (!mobile) setNavigationOpen(false);
  }, [mobile]);
  const acceptSession = (s: Session) => {
    setCSRF(s.csrf_token);
    setSession(s);
  };
  useEffect(() => {
    api<Session>("/auth/session")
      .then(acceptSession)
      .catch(() => {})
      .finally(() => setLoading(false));
    const expired = () => {
      setSession(null);
      setCSRF("");
    };
    window.addEventListener("session-expired", expired);
    return () => window.removeEventListener("session-expired", expired);
  }, []);
  const reload = async () => {
    const [d, a] = await Promise.all([
      api<Draft>("/config/draft"),
      api<Revision>("/config/active"),
    ]);
    d.bundle = normalizeBundle(d.bundle);
    setDraft(d);
    setActive(normalizeBundle(a.bundle));
    setSelected((current) =>
      d.bundle.sites.some((s) => s.id === current)
        ? current
        : d.bundle.sites[0]?.id || "",
    );
    setDirty(false);
    setLoadError("");
    setRefresh((r) => r + 1);
  };
  useEffect(() => {
    if (session) reload().catch((e) => setLoadError(e.message));
  }, [session?.user.id]);
  useEffect(() => {
    const prevent = (e: BeforeUnloadEvent) => {
      if (dirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", prevent);
    return () => window.removeEventListener("beforeunload", prevent);
  }, [dirty]);
  const change = (sites: Site[]) => {
    if (draft) {
      setDraft({ ...draft, bundle: { ...draft.bundle, sites } });
      setDirty(true);
    }
  };
  const changeSecurity = (security: Security) => {
    if (draft) {
      setDraft({ ...draft, bundle: { ...draft.bundle, security } });
      setDirty(true);
    }
  };
  const save = async () => {
    if (!draft) throw new Error("配置尚未加载");
    const d = await api<Draft>("/config/draft", "PUT", draft);
    d.bundle = normalizeBundle(d.bundle);
    setDraft(d);
    setDirty(false);
    return d;
  };
  const saveClick = async () => {
    setBusy(true);
    try {
      await save();
      message.success("草稿已保存，尚未发布");
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const validate = async () => {
    if (!draft) return;
    setBusy(true);
    try {
      await api("/config/validate", "POST", draft.bundle);
      message.success("配置校验通过");
    } catch (e) {
      Modal.error({
        title: "配置校验失败",
        content: (e as Error).message,
        width: 700,
      });
    } finally {
      setBusy(false);
    }
  };
  const publish = async () => {
    if (!draft) return;
    setBusy(true);
    try {
      const d = dirty ? await save() : draft;
      const result = await api<{ revision: number; warning?: string }>(
        "/config/publish",
        "POST",
        { version: d.version, base_revision: d.base_revision },
      );
      if (result.warning) message.warning(result.warning);
      else message.success(`配置版本 ${result.revision} 已发布`);
      await reload();
    } catch (e) {
      Modal.error({
        title: "发布失败，现有配置继续运行",
        content: (e as Error).message,
        width: 700,
      });
    } finally {
      setBusy(false);
    }
  };
  const rollback = async (revision: number) => {
    if (!draft) return;
    setBusy(true);
    try {
      await api("/config/rollback", "POST", {
        revision,
        version: draft.version,
        base_revision: draft.base_revision,
      });
      await reload();
      message.success("配置已回滚并发布");
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const logout = async () => {
    try {
      await api("/auth/logout", "POST", {});
      setSession(null);
      setDraft(undefined);
      setCSRF("");
    } catch (e) {
      message.error((e as Error).message);
    }
  };
  if (loading)
    return (
      <div className="full-loading">
        <Spin size="large" />
      </div>
    );
  if (!session) return <Login onLogin={acceptSession} />;
  const editable = session.user.role !== "viewer";
  const admin = session.user.role === "admin";
  const props: PolicyProps = {
    security: draft?.bundle.security || defaultSecurity(),
    sites: draft?.bundle.sites || [],
    selected,
    select: setSelected,
    change,
    editable,
  };
  const menu = [
    {
      key: "overview",
      icon: <DashboardOutlined aria-hidden="true" />,
      label: "安全概览",
    },
    {
      key: "sites",
      icon: <GlobalOutlined aria-hidden="true" />,
      label: "站点管理",
    },
    {
      type: "group" as const,
      label: "安全策略",
      children: [
        {
          key: "security",
          icon: <SecurityScanOutlined aria-hidden="true" />,
          label: "安全规则",
        },
        {
          key: "routes",
          icon: <ApiOutlined aria-hidden="true" />,
          label: "路径与流式策略",
        },
      ],
    },
    {
      type: "group" as const,
      label: "运行与管理",
      children: [
        {
          key: "events",
          icon: <FileSearchOutlined aria-hidden="true" />,
          label: "安全事件",
        },
        {
          key: "certificates",
          icon: <KeyOutlined aria-hidden="true" />,
          label: "证书与凭据",
        },
        {
          key: "revisions",
          icon: <HistoryOutlined aria-hidden="true" />,
          label: "配置版本",
        },
        {
          key: "audit",
          icon: <AuditOutlined aria-hidden="true" />,
          label: "操作审计",
        },
        ...(admin
          ? [
              {
                key: "users",
                icon: <TeamOutlined aria-hidden="true" />,
                label: "用户与权限",
              },
              {
                key: "backups",
                icon: <CloudServerOutlined aria-hidden="true" />,
                label: "备份与运维",
              },
            ]
          : []),
      ],
    },
  ];
  const titles: Record<string, string> = {
    overview: "安全概览",
    sites: "站点管理",
    security: "安全规则",
    routes: "路径与流式策略",
    events: "安全事件",
    certificates: "证书与凭据",
    revisions: "配置版本",
    audit: "操作审计",
    users: "用户与权限",
    backups: "备份与运维",
  };
  const addExclusion = (event: SecurityEvent, target: string, path: string) => {
    const site = props.sites.find((s) => s.id === event.site_id);
    if (!site) {
      message.error("站点已不在当前草稿中");
      return;
    }
    const security = props.security;
    const policyID = event.managed_policy_id;
    const policy =
      policyID === "default"
        ? security.managed.default
        : security.managed.overrides.find((o) => o.id === policyID)?.policy;
    if (!policy || !policyID) {
      message.error("事件对应的托管策略已不在当前草稿中");
      return;
    }
    const next = {
      ...policy,
      exclusions: [
        ...policy.exclusions,
        {
          scope: { mode: "sites" as const, site_ids: [site.id] },
          rule_id: Number(event.rule_id),
          path_prefix: path,
          target,
        },
      ],
    };
    changeSecurity({
      ...security,
      managed:
        policyID === "default"
          ? { ...security.managed, default: next }
          : {
              ...security.managed,
              overrides: security.managed.overrides.map((o) =>
                o.id === policyID ? { ...o, policy: next } : o,
              ),
            },
    });
    setManagedRequest({ id: policyID, nonce: Date.now() });
    setPage("security");
    message.success("例外已加入草稿，请检查范围后发布");
  };
  let content: React.ReactNode;
  switch (page) {
    case "sites":
      content = <SitesPage {...props} />;
      break;
    case "security":
      content = (
        <SecurityRulesPage
          sites={props.sites}
          security={props.security}
          change={changeSecurity}
          editable={editable}
          managedRequest={managedRequest}
          onManagedClose={() => setManagedRequest(null)}
        />
      );
      break;
    case "routes":
      content = <RoutesPage {...props} />;
      break;
    case "events":
      content = (
        <EventsPage
          sites={props.sites}
          editable={editable}
          addExclusion={addExclusion}
        />
      );
      break;
    case "certificates":
      content = <CertificatesPage admin={admin} />;
      break;
    case "users":
      content = admin ? <UsersPage /> : null;
      break;
    case "audit":
      content = <AuditPage />;
      break;
    case "backups":
      content = admin ? <BackupsPage /> : null;
      break;
    case "revisions":
      content = (
        <RevisionsPage
          editable={editable}
          onRollback={rollback}
          refresh={refresh}
        />
      );
      break;
    default:
      content = (
        <OverviewPage
          sites={active.sites}
          security={active.security}
          refresh={refresh}
        />
      );
  }
  const navigation = (
    <Menu
      theme="dark"
      mode="inline"
      selectedKeys={[page]}
      onClick={({ key }) => {
        setPage(key);
        setManagedRequest(null);
        setNavigationOpen(false);
      }}
      items={menu}
    />
  );
  return (
    <Layout className="console-layout">
      {mobile ? (
        <Drawer
          title="WAF 控制台"
          placement="left"
          size={272}
          open={navigationOpen}
          onClose={() => setNavigationOpen(false)}
          classNames={{ section: "navigation-drawer" }}
          styles={{ body: { padding: "8px 0" } }}
          closable={{ "aria-label": "关闭导航" }}
        >
          {navigation}
        </Drawer>
      ) : (
        <Layout.Sider
          width={224}
          collapsed={collapsed}
          collapsible
          onCollapse={setCollapsed}
          breakpoint="lg"
          className="sidebar"
        >
          <div className="sidebar-brand">
            <SecurityScanOutlined aria-hidden="true" />
            {!collapsed && (
              <span>
                WAF <small>控制台</small>
              </span>
            )}
          </div>
          {navigation}
        </Layout.Sider>
      )}
      <Layout className="main-layout">
        <Layout.Header className="topbar">
          <div className="topbar-heading">
            {mobile && (
              <Button
                type="text"
                icon={<MenuOutlined aria-hidden="true" />}
                aria-label="打开导航"
                aria-expanded={navigationOpen}
                onClick={() => setNavigationOpen(true)}
              />
            )}
            <Title level={1}>{titles[page]}</Title>
          </div>
          <Space size={12} className="topbar-account">
            {session.development && (
              <Tag color="orange" className="development-tag">
                开发模式
              </Tag>
            )}
            <Dropdown
              trigger={["click"]}
              menu={{
                items: [
                  {
                    key: "user",
                    label: `${session.user.username} · ${{ admin: "管理员", operator: "操作员", viewer: "只读用户" }[session.user.role]}`,
                    disabled: true,
                  },
                  {
                    key: "logout",
                    icon: <LogoutOutlined aria-hidden="true" />,
                    label: "退出登录",
                    onClick: () => void logout(),
                  },
                ],
              }}
            >
              <button
                type="button"
                className="user-menu"
                aria-label={`账户：${session.user.username}`}
              >
                <Avatar
                  size="small"
                  icon={<UserOutlined aria-hidden="true" />}
                />
                <span className="user-name">{session.user.username}</span>
              </button>
            </Dropdown>
          </Space>
        </Layout.Header>
        <Layout.Content className="content">
          {loadError ? (
            <Alert
              type="error"
              showIcon
              title="配置加载失败"
              description={loadError}
              action={
                <Button
                  onClick={() =>
                    void reload().catch((e) => message.error(e.message))
                  }
                >
                  重试
                </Button>
              }
            />
          ) : (
            <>
              <div className={`draft-bar ${dirty ? "changed" : ""}`}>
                <div className="draft-status" aria-live="polite">
                  <Space>
                    <span className="status-dot" />
                    <Text>
                      {!draft
                        ? "正在加载配置"
                        : dirty
                          ? "有未保存的修改"
                          : "草稿已保存"}
                    </Text>
                  </Space>
                  {draft && (
                    <Text type="secondary" className="draft-version">
                      基于配置 v{draft.base_revision} · 草稿 #{draft.version}
                    </Text>
                  )}
                </div>
                <div className="draft-actions">
                  <Button
                    type="text"
                    disabled={!draft || busy}
                    onClick={() => {
                      if (dirty)
                        Modal.confirm({
                          title: "放弃未保存的修改并重新加载？",
                          onOk: reload,
                        });
                      else void reload().catch((e) => message.error(e.message));
                    }}
                  >
                    重新加载
                  </Button>
                  {editable && (
                    <>
                      <Button
                        icon={<SaveOutlined aria-hidden="true" />}
                        disabled={!dirty || busy}
                        onClick={() => void saveClick()}
                      >
                        保存草稿
                      </Button>
                      <Button
                        disabled={!draft || busy}
                        onClick={() => void validate()}
                      >
                        校验配置
                      </Button>
                      <Button
                        type="primary"
                        icon={<SendOutlined aria-hidden="true" />}
                        loading={busy}
                        disabled={!draft}
                        onClick={() =>
                          Modal.confirm({
                            title: "发布当前配置？",
                            content:
                              "网站配置与全局安全规则将在校验通过后一起生效。已建立的 SSE 和 WebSocket 连接继续使用原配置。",
                            okText: "校验并发布",
                            onOk: publish,
                          })
                        }
                      >
                        发布配置
                      </Button>
                    </>
                  )}
                </div>
              </div>
              {editable && (
                <Paragraph type="secondary" className="draft-note">
                  站点和策略修改发布后生效；凭据和账号修改立即生效。
                </Paragraph>
              )}
              {draft ? content : <Spin />}
            </>
          )}
        </Layout.Content>
      </Layout>
    </Layout>
  );
}
createRoot(document.getElementById("root")!).render(
  <ConfigProvider
    button={{ autoInsertSpace: false }}
    locale={zhCN}
    theme={{
      token: {
        colorPrimary: "#087f72",
        colorInfo: "#087f72",
        borderRadius: 8,
        fontFamily:
          'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
        colorBgLayout: "#f3f5f8",
        colorText: "#24334b",
      },
      components: {
        Layout: { headerBg: "#ffffff", siderBg: "#102036" },
        Menu: {
          darkItemBg: "#102036",
          darkSubMenuItemBg: "#102036",
          darkItemSelectedBg: "#164739",
          darkItemSelectedColor: "#8ee1c6",
        },
        Table: { headerBg: "#f7f9fc" },
        Button: { controlHeight: 36 },
      },
    }}
  >
    <AntApp>
      <Console />
    </AntApp>
  </ConfigProvider>,
);
