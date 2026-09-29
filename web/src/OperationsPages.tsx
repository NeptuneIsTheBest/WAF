import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Form,
  Input,
  Modal,
  Popconfirm,
  QRCode,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import {
  CloudDownloadOutlined,
  CloudUploadOutlined,
  PlusOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import { actionColor, actionNames, api, timestamp } from "./api";
import type {
  Audit,
  Certificate,
  Overview,
  Revision,
  SecurityEvent,
  Site,
  User,
} from "./types";
const { Text, Paragraph } = Typography;
export function OverviewPage({
  sites,
  refresh,
}: {
  sites: Site[];
  refresh: number;
}) {
  const [data, setData] = useState<Overview>();
  const [error, setError] = useState("");
  useEffect(() => {
    const load = () =>
      api<Overview>("/overview")
        .then((value) => {
          setData(value);
          setError("");
        })
        .catch((e) => setError(e.message));
    void load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [refresh]);
  const stats = data?.stats || {};
  const total = Object.entries(stats)
    .filter(([k]) => !k.startsWith("log_"))
    .reduce((n, [, v]) => n + v, 0);
  const blocked =
    (stats.block || 0) + (stats.rate_limit || 0) + (stats.resource_limit || 0);
  const active = sites.filter((s) => s.enabled);
  const observe = active.filter((s) => s.managed.mode === "observe");
  return (
    <Space orientation="vertical" size={16} className="full-width">
      {error && <Alert type="error" title={error} />}
      <div className="overview-meta">
        <Space size={16} wrap>
          <Text type="secondary">当前配置 v{data?.revision ?? "—"}</Text>
          <Text type="secondary">OWASP CRS {data?.crs_version || "—"}</Text>
        </Space>
        <Text type="secondary">请求统计：最近 24 小时</Text>
      </div>
      <Row gutter={[16, 16]}>
        {[
          {
            title: "已记录请求",
            value: total,
            note: "受日志保留和容量限制",
          },
          {
            title: "拦截与限流",
            value: blocked,
            note: total
              ? `${((blocked / total) * 100).toFixed(1)}% 的已记录请求`
              : "暂无请求记录",
          },
          {
            title: "浏览器挑战",
            value:
              (stats.managed_challenge || 0) +
              (stats.non_interactive_challenge || 0) +
              (stats.interactive_challenge || 0),
            note: "要求浏览器验证的请求",
          },
          {
            title: "启用站点",
            value: active.length,
            note: `${observe.length} 个站点处于观察模式`,
          },
        ].map((x) => (
          <Col xs={12} xl={6} key={x.title}>
            <Card className="stat-card" loading={!data && !error}>
              <Statistic title={x.title} value={x.value} />
              <Text type="secondary">{x.note}</Text>
            </Card>
          </Col>
        ))}
      </Row>
      {observe.length > 0 && (
        <Alert
          showIcon
          type="warning"
          title={`${observe.length} 个站点处于观察模式`}
          description="托管规则只记录命中，不拦截请求。确认无误报后，可切换为拦截模式并发布。"
        />
      )}
      {((stats.log_dropped || 0) > 0 || (stats.log_write_errors || 0) > 0) && (
        <Alert
          showIcon
          type="error"
          title="部分日志未能保存"
          description={`丢弃 ${stats.log_dropped || 0} 条，写入失败 ${stats.log_write_errors || 0} 次。请检查磁盘与日志负载。`}
        />
      )}
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card
            title="上游状态"
            extra={<Tag>{data?.upstreams.length || 0} 个上游</Tag>}
          >
            <Table
              rowKey={(r) => r.site_id + r.url}
              dataSource={data?.upstreams || []}
              pagination={false}
              scroll={{ x: 500 }}
              locale={{ emptyText: "暂无已发布的上游" }}
              columns={[
                { title: "站点", dataIndex: "site_id" },
                { title: "地址", dataIndex: "url", ellipsis: true },
                {
                  title: "状态",
                  render: (_, r: { healthy: boolean; health_path: string }) => (
                    <Tag color={r.healthy ? "success" : "error"}>
                      {r.healthy
                        ? r.health_path
                          ? "健康"
                          : "可用 · 被动检查"
                        : "暂不可用"}
                    </Tag>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="请求处理结果">
            <div className="distribution">
              {[
                "allow",
                "block",
                "observe",
                "managed_challenge",
                "non_interactive_challenge",
                "interactive_challenge",
                "rate_limit",
                "error",
              ].map((k) => (
                <div className="distribution-row" key={k}>
                  <span>{actionNames[k]}</span>
                  <div className={`distribution-track ${k}`}>
                    <i
                      style={{
                        width: `${total ? ((stats[k] || 0) / total) * 100 : 0}%`,
                      }}
                    />
                  </div>
                  <strong>{stats[k] || 0}</strong>
                </div>
              ))}
            </div>
            <Paragraph type="secondary" className="form-top">
              仅统计已保存的事件。完整计数见 Prometheus 指标。
            </Paragraph>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
export function CertificatesPage({ admin }: { admin: boolean }) {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [credentials, setCredentials] = useState<
    { name: string; updated: string }[]
  >([]);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();
  const load = () => {
    api<Certificate[]>("/certificates")
      .then(setCerts)
      .catch((e) => message.error(e.message));
    if (admin)
      api<{ name: string; updated: string }[]>("/credentials")
        .then(setCredentials)
        .catch((e) => message.error(e.message));
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [admin]);
  const save = async () => {
    const v = await form.validateFields();
    setSaving(true);
    try {
      await api("/credentials/" + encodeURIComponent(v.name), "PUT", {
        api_token: v.api_token,
        zone_token: v.zone_token || "",
      });
      message.success("凭据已加密保存");
      setOpen(false);
      form.resetFields();
      load();
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  };
  return (
    <Space orientation="vertical" size={20} className="full-width">
      <Card
        title="HTTPS 证书"
        extra={
          <Button icon={<ReloadOutlined aria-hidden="true" />} onClick={load}>
            刷新
          </Button>
        }
      >
        <Table
          rowKey="domain"
          dataSource={certs}
          pagination={false}
          scroll={{ x: 800 }}
          columns={[
            { title: "域名", dataIndex: "domain" },
            {
              title: "状态",
              render: (_, c: Certificate) => (
                <Space>
                  <Tag
                    color={
                      c.state === "active"
                        ? "success"
                        : c.state === "error" || c.state === "expired"
                          ? "error"
                          : "warning"
                    }
                  >
                    {(
                      {
                        active: "有效",
                        pending: "签发 / 续期中",
                        error: "失败",
                        expired: "已过期",
                        development: "本地开发",
                      } as Record<string, string>
                    )[c.state] || c.state}
                  </Tag>
                  {c.staging && <Tag color="orange">测试 CA</Tag>}
                </Space>
              ),
            },
            { title: "到期时间", dataIndex: "expires", render: timestamp },
            { title: "凭据", dataIndex: "credential" },
            {
              title: "最近事件",
              render: (_, c: Certificate) => (
                <Space orientation="vertical" size={0}>
                  <span>{c.last_event || "—"}</span>
                  {c.last_error && <Text type="danger">{c.last_error}</Text>}
                </Space>
              ),
            },
          ]}
        />
      </Card>
      {admin && (
        <Card
          title="Cloudflare DNS 凭据"
          extra={
            <Button
              icon={<PlusOutlined aria-hidden="true" />}
              onClick={() => {
                form.resetFields();
                setOpen(true);
              }}
            >
              添加或更新凭据
            </Button>
          }
        >
          <Paragraph type="secondary">
            Token 需要目标 Zone 的 DNS:Edit 和 Zone:Read
            权限，也可分别填写。保存后不再显示 Token。
          </Paragraph>
          <Table
            rowKey="name"
            dataSource={credentials}
            pagination={false}
            scroll={{ x: 500 }}
            columns={[
              { title: "名称", dataIndex: "name" },
              { title: "更新时间", dataIndex: "updated", render: timestamp },
              {
                title: "操作",
                render: (_, r: { name: string }) => (
                  <Button
                    size="small"
                    onClick={() => {
                      form.resetFields();
                      form.setFieldValue("name", r.name);
                      setOpen(true);
                    }}
                  >
                    更新 Token
                  </Button>
                ),
              },
            ]}
          />
        </Card>
      )}
      <Modal
        title="Cloudflare API 凭据"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        confirmLoading={saving}
        okText="保存"
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="凭据名称"
            rules={[{ required: true }, { pattern: /^[A-Za-z0-9_-]{1,64}$/ }]}
          >
            <Input placeholder="cloudflare" />
          </Form.Item>
          <Form.Item
            name="api_token"
            label="DNS API Token"
            rules={[{ required: true }]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="zone_token" label="Zone:Read Token（可选）">
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
export function EventsPage({
  sites,
  editable,
  addExclusion,
}: {
  sites: Site[];
  editable: boolean;
  addExclusion: (event: SecurityEvent, target: string, path: string) => void;
}) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [site, setSite] = useState<string>();
  const [action, setAction] = useState<string>();
  const [cursor, setCursor] = useState(0);
  const [history, setHistory] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState<SecurityEvent | null>(null);
  const [exception, setException] = useState<SecurityEvent | null>(null);
  const [form] = Form.useForm();
  const load = () => {
    setLoading(true);
    api<SecurityEvent[]>(
      "/events?" +
        new URLSearchParams({
          site_id: site || "",
          action: action || "",
          before: String(cursor),
        }),
    )
      .then(setEvents)
      .catch((e) => message.error(e.message))
      .finally(() => setLoading(false));
  };
  useEffect(load, [site, action, cursor]);
  return (
    <>
      <Card
        title="事件记录"
        extra={
          <div className="filter-bar">
            <Select
              allowClear
              placeholder="全部站点"
              value={site}
              onChange={(v) => {
                setSite(v);
                setCursor(0);
                setHistory([]);
              }}
              style={{ width: 170 }}
              options={sites.map((s) => ({
                value: s.id,
                label: s.name || s.id,
              }))}
            />
            <Select
              allowClear
              placeholder="全部动作"
              value={action}
              onChange={(v) => {
                setAction(v);
                setCursor(0);
                setHistory([]);
              }}
              style={{ width: 150 }}
              options={Object.entries(actionNames).map(([value, label]) => ({
                value,
                label,
              }))}
            />
            <Button
              icon={<ReloadOutlined aria-hidden="true" />}
              onClick={() => {
                if (cursor) {
                  setCursor(0);
                  setHistory([]);
                } else load();
              }}
            >
              刷新
            </Button>
          </div>
        }
      >
        <Table
          rowKey="id"
          dataSource={events}
          loading={loading}
          size="small"
          pagination={false}
          scroll={{ x: 1050 }}
          columns={[
            { title: "时间", dataIndex: "time", render: timestamp, width: 170 },
            { title: "客户端 IP", dataIndex: "client_ip", width: 145 },
            {
              title: "请求",
              render: (_, e: SecurityEvent) => (
                <Space orientation="vertical" size={0}>
                  <span>
                    <Tag>{e.method}</Tag>
                    <Text>{e.path}</Text>
                  </span>
                  <Text type="secondary" className="small">
                    {e.site_id}
                  </Text>
                </Space>
              ),
            },
            {
              title: "动作",
              render: (_, e: SecurityEvent) => (
                <Tag color={actionColor[e.action]}>
                  {actionNames[e.action] || e.action}
                </Tag>
              ),
              width: 210,
            },
            { title: "状态", dataIndex: "status", width: 60 },
            { title: "规则", dataIndex: "rule_id", width: 85 },
            {
              title: "耗时",
              render: (_, e: SecurityEvent) => `${e.duration_ms} ms`,
              width: 90,
            },
            {
              title: "详情",
              render: (_, e: SecurityEvent) => (
                <Button size="small" onClick={() => setDetail(e)}>
                  查看
                </Button>
              ),
              width: 75,
            },
          ]}
        />
        <Space className="form-top">
          <Button
            disabled={!history.length}
            onClick={() => {
              setCursor(history[history.length - 1]);
              setHistory(history.slice(0, -1));
            }}
          >
            更新的事件
          </Button>
          <Button
            disabled={events.length < 100}
            onClick={() => {
              setHistory([...history, cursor]);
              setCursor(events[events.length - 1].id);
            }}
          >
            更早的事件
          </Button>
        </Space>
      </Card>
      <Modal
        title="事件详情"
        open={!!detail}
        onCancel={() => setDetail(null)}
        width={760}
        footer={
          detail && editable && Number(detail.rule_id) >= 900000 ? (
            <Space>
              <Button onClick={() => setDetail(null)}>关闭</Button>
              <Button
                type="primary"
                onClick={() => {
                  setException(detail);
                  form.setFieldsValue({ path_prefix: detail.path, target: "" });
                  setDetail(null);
                }}
              >
                添加规则例外
              </Button>
            </Space>
          ) : (
            <Button onClick={() => setDetail(null)}>关闭</Button>
          )
        }
      >
        {detail && (
          <>
            <Descriptions
              column={2}
              bordered
              size="small"
              items={[
                {
                  key: "request",
                  label: "请求 ID",
                  children: detail.request_id,
                  span: 2,
                },
                { key: "site", label: "站点", children: detail.site_id },
                {
                  key: "revision",
                  label: "配置版本",
                  children: detail.revision,
                },
                { key: "ip", label: "客户端 IP", children: detail.client_ip },
                {
                  key: "action",
                  label: "动作",
                  children: actionNames[detail.action],
                },
                ...(detail.challenge_mode
                  ? [
                      {
                        key: "challenge_mode",
                        label: "实际验证方式",
                        children:
                          detail.challenge_mode === "interactive"
                            ? "点击验证"
                            : "自动验证",
                        span: 2,
                      },
                    ]
                  : []),
                { key: "path", label: "路径", children: detail.path, span: 2 },
                {
                  key: "rule",
                  label: "规则 ID",
                  children: detail.rule_id || "—",
                },
                {
                  key: "inspection",
                  label: "检查范围",
                  children: detail.inspection,
                },
                {
                  key: "message",
                  label: "原因",
                  children: detail.message || "—",
                  span: 2,
                },
                { key: "bytes", label: "响应字节数", children: detail.bytes },
                {
                  key: "duration",
                  label: "完整耗时",
                  children: `${detail.duration_ms} ms`,
                },
              ]}
            />
            <Paragraph type="secondary" className="form-top">
              事件不保存请求正文、Cookie、Authorization 和查询参数值；不检查
              WebSocket 消息内容。
            </Paragraph>
          </>
        )}
      </Modal>
      <Modal
        title={`为规则 ${exception?.rule_id || ""} 添加例外`}
        open={!!exception}
        onCancel={() => setException(null)}
        onOk={async () => {
          const v = await form.validateFields();
          if (exception)
            addExclusion(exception, v.target || "", v.path_prefix || "");
          setException(null);
        }}
        okText="加入草稿"
      >
        <Alert
          type="warning"
          showIcon
          title="检查例外范围后再发布"
          description="例外按路径前缀匹配，填写参数可缩小跳过范围。"
        />
        <Form form={form} layout="vertical" className="form-top">
          <Form.Item name="path_prefix" label="路径前缀">
            <Input />
          </Form.Item>
          <Form.Item name="target" label="参数限定">
            <Input placeholder="例如 ARGS:comment" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
export function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [open, setOpen] = useState(false);
  const [enrollment, setEnrollment] = useState<{
    user: User;
    totp_secret: string;
    otpauth_url: string;
    recovery_codes: string[];
  }>();
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();
  const load = () =>
    api<User[]>("/users")
      .then(setUsers)
      .catch((e) => message.error(e.message));
  useEffect(() => {
    void load();
  }, []);
  const create = async () => {
    const v = await form.validateFields();
    setSaving(true);
    try {
      const result = await api<typeof enrollment>("/users", "POST", v);
      setEnrollment(result);
      setOpen(false);
      form.resetFields();
      void load();
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  };
  const change = async (u: User, role = u.role, disabled = u.disabled) => {
    try {
      await api("/users/" + u.id, "PATCH", { role, disabled });
      message.success("账号已更新，原会话已失效");
      void load();
    } catch (e) {
      message.error((e as Error).message);
    }
  };
  return (
    <>
      <Card
        title="用户与权限"
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined aria-hidden="true" />}
            onClick={() => {
              form.resetFields();
              form.setFieldValue("role", "viewer");
              setOpen(true);
            }}
          >
            添加用户
          </Button>
        }
      >
        <Alert
          type="info"
          showIcon
          title="角色权限"
          description="管理员管理账号与凭据；操作员管理站点和规则；只读用户查看状态与事件。"
        />
        <Table
          rowKey="id"
          dataSource={users}
          pagination={false}
          scroll={{ x: 650 }}
          className="form-top"
          columns={[
            { title: "用户名", dataIndex: "username" },
            {
              title: "角色",
              render: (_, u: User) => (
                <Select
                  value={u.role}
                  style={{ width: 130 }}
                  onChange={(role) => void change(u, role)}
                  options={[
                    { value: "admin", label: "管理员" },
                    { value: "operator", label: "操作员" },
                    { value: "viewer", label: "只读用户" },
                  ]}
                />
              ),
            },
            {
              title: "状态",
              render: (_, u: User) => (
                <Tag color={u.disabled ? "default" : "success"}>
                  {u.disabled ? "已停用" : "正常"}
                </Tag>
              ),
            },
            { title: "创建时间", dataIndex: "created", render: timestamp },
            {
              title: "操作",
              render: (_, u: User) => (
                <Popconfirm
                  title={
                    u.disabled ? "重新启用此账号？" : "停用此账号并撤销会话？"
                  }
                  onConfirm={() => change(u, u.role, !u.disabled)}
                >
                  <Button size="small" danger={!u.disabled}>
                    {u.disabled ? "启用" : "停用"}
                  </Button>
                </Popconfirm>
              ),
            },
          ]}
        />
      </Card>
      <Modal
        title="添加用户"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void create()}
        confirmLoading={saving}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: true }, { pattern: /^[A-Za-z0-9_-]{1,64}$/ }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="password"
            label="初始密码"
            rules={[{ required: true }, { min: 12, max: 256 }]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="role" label="角色">
            <Select
              options={[
                { value: "viewer", label: "只读用户" },
                { value: "operator", label: "操作员" },
                { value: "admin", label: "管理员" },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title="保存登录验证信息"
        open={!!enrollment}
        onCancel={() => setEnrollment(undefined)}
        footer={
          <Button type="primary" onClick={() => setEnrollment(undefined)}>
            已保存
          </Button>
        }
        width={650}
      >
        {enrollment && (
          <>
            <Alert
              type="warning"
              title="验证信息只显示一次，请保存后通过安全渠道交给用户。"
            />
            <Row gutter={24} className="form-top">
              <Col xs={24} md={10}>
                <QRCode value={enrollment.otpauth_url} />
              </Col>
              <Col xs={24} md={14}>
                <Text strong>{enrollment.user.username}</Text>
                <Paragraph copyable>{enrollment.totp_secret}</Paragraph>
                <Text strong>一次性恢复码</Text>
                <Paragraph className="recovery-codes" copyable>
                  {enrollment.recovery_codes.join("\n")}
                </Paragraph>
              </Col>
            </Row>
          </>
        )}
      </Modal>
    </>
  );
}
export function AuditPage() {
  const [rows, setRows] = useState<Audit[]>([]);
  const [before, setBefore] = useState(0);
  const load = () =>
    api<Audit[]>("/audit?before=" + before)
      .then(setRows)
      .catch((e) => message.error(e.message));
  useEffect(() => {
    void load();
  }, [before]);
  return (
    <Card
      title="操作审计"
      extra={
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          onClick={() => {
            if (before) setBefore(0);
            else void load();
          }}
        >
          刷新
        </Button>
      }
    >
      <Table
        rowKey="id"
        dataSource={rows}
        pagination={false}
        scroll={{ x: 600 }}
        columns={[
          { title: "时间", dataIndex: "time", render: timestamp },
          { title: "操作者", dataIndex: "actor" },
          { title: "操作", dataIndex: "action" },
          { title: "详情", dataIndex: "detail" },
        ]}
      />
      <Button
        className="form-top"
        disabled={rows.length < 100}
        onClick={() => setBefore(rows[rows.length - 1].id)}
      >
        查看更早记录
      </Button>
    </Card>
  );
}
export function RevisionsPage({
  editable,
  onRollback,
  refresh,
}: {
  editable: boolean;
  onRollback: (id: number) => Promise<void>;
  refresh: number;
}) {
  const [rows, setRows] = useState<Revision[]>([]);
  useEffect(() => {
    api<Revision[]>("/config/revisions")
      .then(setRows)
      .catch((e) => message.error(e.message));
  }, [refresh]);
  return (
    <Card title="配置版本与回滚">
      <Alert
        type="info"
        showIcon
        title="回滚将创建并发布新版本"
        description="回滚会替换当前草稿，并使用当前 CRS 校验。规则集不会降级，旧通行凭证不会恢复。"
      />
      <Table
        rowKey="id"
        dataSource={rows}
        pagination={{ pageSize: 20 }}
        scroll={{ x: 600 }}
        className="form-top"
        columns={[
          {
            title: "版本",
            dataIndex: "id",
            render: (v: number) => <Tag color="blue">v{v}</Tag>,
          },
          { title: "发布时间", dataIndex: "created", render: timestamp },
          { title: "操作者", dataIndex: "actor" },
          { title: "CRS", dataIndex: "crs_version" },
          {
            title: "操作",
            render: (_, r: Revision) => (
              <Popconfirm
                title={`恢复版本 ${r.id} 的配置并发布？当前草稿将被替换。`}
                onConfirm={() => onRollback(r.id)}
              >
                <Button size="small" disabled={!editable}>
                  恢复此配置
                </Button>
              </Popconfirm>
            ),
          },
        ]}
      />
    </Card>
  );
}
export function BackupsPage() {
  const [rows, setRows] = useState<
    { name: string; size: number; created: string }[]
  >([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm();
  const load = () =>
    api<typeof rows>("/backups")
      .then(setRows)
      .catch((e) => message.error(e.message));
  useEffect(() => {
    void load();
  }, []);
  const create = async () => {
    const v = await form.validateFields();
    setBusy(true);
    try {
      await api("/backups", "POST", { password: v.password });
      message.success("加密备份已生成");
      setOpen(false);
      form.resetFields();
      void load();
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Space orientation="vertical" size={20} className="full-width">
      <Alert
        type="warning"
        showIcon
        title="请同时备份 master.key"
        description="备份包含配置、账号、事件和证书，使用独立密码加密。恢复还需要原始 master.key，请将两者保存到其他机器。"
      />
      <Card
        title="加密备份"
        extra={
          <Button
            type="primary"
            icon={<CloudUploadOutlined aria-hidden="true" />}
            onClick={() => {
              form.resetFields();
              setOpen(true);
            }}
          >
            创建备份
          </Button>
        }
      >
        <Table
          rowKey="name"
          dataSource={rows}
          pagination={false}
          scroll={{ x: 550 }}
          columns={[
            { title: "文件", dataIndex: "name" },
            { title: "创建时间", dataIndex: "created", render: timestamp },
            {
              title: "大小",
              dataIndex: "size",
              render: (n: number) => `${(n / 1024 / 1024).toFixed(2)} MiB`,
            },
            {
              title: "操作",
              render: (_, r: { name: string }) => (
                <Button
                  icon={<CloudDownloadOutlined aria-hidden="true" />}
                  href={"/api/v1/backups/" + encodeURIComponent(r.name)}
                >
                  下载
                </Button>
              ),
            },
          ]}
        />
      </Card>
      <Card title="恢复与运行诊断">
        <Paragraph>
          先停止服务，再在服务器上执行恢复命令。恢复前的旧数据会另存为副本。
        </Paragraph>
        <pre className="command-block">
          {
            "sudo systemctl stop waf\nwaf restore --config /etc/waf/waf.json --in backup.age\nwaf check --config /etc/waf/waf.json\nsudo systemctl start waf\nwaf doctor --config /etc/waf/waf.json"
          }
        </pre>
        <Paragraph type="secondary">
          健康检查和 Prometheus 指标默认位于本机
          127.0.0.1:9090，不对公网开放。后台最多保留 10
          个备份，旧文件由本机管理员归档清理。
        </Paragraph>
      </Card>
      <Modal
        title="创建加密备份"
        open={open}
        onCancel={() => {
          if (!busy) setOpen(false);
        }}
        onOk={() => void create()}
        confirmLoading={busy}
        okText="生成备份"
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="password"
            label="备份加密密码"
            rules={[{ required: true }, { min: 12, max: 256 }]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirmation"
            label="再次输入密码"
            dependencies={["password"]}
            rules={[
              { required: true },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  return value === getFieldValue("password")
                    ? Promise.resolve()
                    : Promise.reject(new Error("两次密码不同"));
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
