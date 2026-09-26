import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Alert,
  App as AntApp,
  Avatar,
  Button,
  ConfigProvider,
  Dropdown,
  Form,
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
  FileProtectOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  HistoryOutlined,
  KeyOutlined,
  LogoutOutlined,
  RobotOutlined,
  SaveOutlined,
  SecurityScanOutlined,
  SendOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { api, setCSRF } from "./api";
import { normalizeSite } from "./types";
import type { Draft, Revision, SecurityEvent, Session, Site } from "./types";
import {
  BotPage,
  CustomPage,
  ManagedPage,
  RatePage,
  RoutesPage,
  SitesPage,
} from "./PolicyPages";
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
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login-page">
      <div className="login-brand">
        <div className="brand-mark">
          <SecurityScanOutlined aria-hidden="true" />
        </div>
        <span>
          WAF <small>SECURITY CONSOLE</small>
        </span>
      </div>
      <div className="login-content">
        <div className="login-story">
          <div className="eyebrow">YOUR APPLICATIONS. PROTECTED.</div>
          <h1>
            守护每一次
            <br />
            <span>连接。</span>
          </h1>
          <p>
            统一管理站点、访问策略与安全事件，
            <br />
            让应用防护清晰可见。
          </p>
          <div className="login-features">
            <span>
              <FileProtectOutlined aria-hidden="true" /> OWASP 托管规则
            </span>
            <span>
              <ThunderboltOutlined aria-hidden="true" /> 实时流量防护
            </span>
            <span>
              <KeyOutlined aria-hidden="true" /> 自动 HTTPS
            </span>
          </div>
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
        </div>
        <div className="login-card">
          <Title level={2}>登录安全控制台</Title>
          <Paragraph type="secondary">
            使用管理员提供的账号与双因素认证。
          </Paragraph>
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
                placeholder="admin"
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
              label="动态验证码或恢复码"
              extra="公网环境必须填写；本地开发模式允许留空。"
            >
              <Input
                size="large"
                autoComplete="one-time-code"
                placeholder="6 位 TOTP 或一次性恢复码"
              />
            </Form.Item>
            <Button
              block
              size="large"
              type="primary"
              htmlType="submit"
              loading={busy}
            >
              安全登录
            </Button>
          </Form>
          <div className="login-help">
            账号初始化与恢复由本机管理员通过 CLI 完成。
          </div>
        </div>
      </div>
      <footer>WAF · 自托管应用安全</footer>
    </div>
  );
}
function Console() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState("overview");
  const [draft, setDraft] = useState<Draft>();
  const [active, setActive] = useState<Site[]>([]);
  const [selected, setSelected] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [loadError, setLoadError] = useState("");
  const [collapsed, setCollapsed] = useState(false);
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
    d.bundle.sites = (d.bundle.sites || []).map(normalizeSite);
    setDraft(d);
    setActive((a.bundle.sites || []).map(normalizeSite));
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
      setDraft({ ...draft, bundle: { sites } });
      setDirty(true);
    }
  };
  const save = async () => {
    if (!draft) throw new Error("配置尚未加载");
    const d = await api<Draft>("/config/draft", "PUT", draft);
    d.bundle.sites = d.bundle.sites.map(normalizeSite);
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
      message.success("全部配置与规则编译校验通过");
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
    sites: draft?.bundle.sites || [],
    selected,
    select: setSelected,
    change,
    editable,
  };
  const menu = [
    { key: "overview", icon: <DashboardOutlined aria-hidden="true" />, label: "安全概览" },
    { key: "sites", icon: <GlobalOutlined aria-hidden="true" />, label: "站点管理" },
    {
      type: "group" as const,
      label: "安全策略",
      children: [
        { key: "managed", icon: <FileProtectOutlined aria-hidden="true" />, label: "托管规则" },
        { key: "custom", icon: <SecurityScanOutlined aria-hidden="true" />, label: "自定义规则" },
        { key: "rate", icon: <ThunderboltOutlined aria-hidden="true" />, label: "请求限流" },
        { key: "bot", icon: <RobotOutlined aria-hidden="true" />, label: "Bot 与浏览器挑战" },
        { key: "routes", icon: <ApiOutlined aria-hidden="true" />, label: "路径与流式策略" },
      ],
    },
    {
      type: "group" as const,
      label: "运行与管理",
      children: [
        { key: "events", icon: <FileSearchOutlined aria-hidden="true" />, label: "安全事件" },
        { key: "certificates", icon: <KeyOutlined aria-hidden="true" />, label: "证书与凭据" },
        { key: "revisions", icon: <HistoryOutlined aria-hidden="true" />, label: "配置版本" },
        { key: "audit", icon: <AuditOutlined aria-hidden="true" />, label: "操作审计" },
        ...(admin
          ? [
              { key: "users", icon: <TeamOutlined aria-hidden="true" />, label: "用户与权限" },
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
    managed: "托管规则",
    custom: "自定义规则",
    rate: "请求限流",
    bot: "Bot 与浏览器挑战",
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
    change(
      props.sites.map((s) =>
        s.id === site.id
          ? {
              ...s,
              managed: {
                ...s.managed,
                exclusions: [
                  ...s.managed.exclusions,
                  { rule_id: Number(event.rule_id), path_prefix: path, target },
                ],
              },
            }
          : s,
      ),
    );
    setSelected(site.id);
    setPage("managed");
    message.success("例外已加入草稿，请检查范围后发布");
  };
  let content: React.ReactNode;
  switch (page) {
    case "sites":
      content = <SitesPage {...props} />;
      break;
    case "managed":
      content = <ManagedPage {...props} />;
      break;
    case "custom":
      content = <CustomPage {...props} />;
      break;
    case "rate":
      content = <RatePage {...props} />;
      break;
    case "bot":
      content = <BotPage {...props} />;
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
      content = <OverviewPage sites={active} refresh={refresh} />;
  }
  return (
    <Layout className="console-layout">
      <Layout.Sider
        width={236}
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
              WAF <small>安全控制台</small>
            </span>
          )}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[page]}
          onClick={({ key }) => setPage(key)}
          items={menu}
        />
      </Layout.Sider>
      <Layout className="main-layout">
        <Layout.Header className="topbar">
          <div>
            <Text type="secondary">工作空间</Text>
            <span className="header-separator">/</span>
            <Text strong>{titles[page]}</Text>
          </div>
          <Space size={16}>
            {session.development && <Tag color="orange">本地开发模式</Tag>}
            <Tag color="cyan">单机节点</Tag>
            <Dropdown
              menu={{
                items: [
                  {
                    key: "user",
                    label: `${session.user.username} · ${session.user.role}`,
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
              <Space className="user-menu">
                <Avatar size="small" icon={<UserOutlined aria-hidden="true" />} />
                <Text>{session.user.username}</Text>
              </Space>
            </Dropdown>
          </Space>
        </Layout.Header>
        <Layout.Content className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">WAF CONTROL CENTER</div>
              <Title level={3}>{titles[page]}</Title>
            </div>
            <Space wrap>
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
                          "所有站点的草稿将在校验通过后生效。既有 SSE 和 WebSocket 连接继续使用当前连接配置。",
                        okText: "校验并发布",
                        onOk: publish,
                      })
                    }
                  >
                    发布配置
                  </Button>
                </>
              )}
            </Space>
          </div>
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
                <Space>
                  <span className="status-dot" />
                  <Text>{dirty ? "有未保存的修改" : "草稿已与服务器同步"}</Text>
                  <Text type="secondary">
                    基于配置 v{draft?.base_revision || 0} · 草稿 #
                    {draft?.version || 0}
                  </Text>
                </Space>
                <Button
                  type="link"
                  size="small"
                  onClick={() => {
                    if (dirty)
                      Modal.confirm({
                        title: "放弃本地未保存修改并重新加载？",
                        onOk: reload,
                      });
                    else void reload().catch((e) => message.error(e.message));
                  }}
                >
                  重新加载
                </Button>
              </div>
              {editable && (
                <Paragraph type="secondary" className="draft-note">
                  站点与策略修改先进入草稿，发布后才影响流量。证书凭据与账号设置即时生效。
                </Paragraph>
              )}
              {draft ? content : <Spin />}
            </>
          )}
        </Layout.Content>
        <Layout.Footer className="footer">
          WAF · Go 反向代理与 OWASP CRS <span>配置可追溯 · 流式连接可观测</span>
        </Layout.Footer>
      </Layout>
    </Layout>
  );
}
createRoot(document.getElementById("root")!).render(
  <ConfigProvider
    button={{autoInsertSpace:false}}
    locale={zhCN}
    theme={{
      token: {
        colorPrimary: "#087f72",
        colorInfo: "#087f72",
        borderRadius: 9,
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
