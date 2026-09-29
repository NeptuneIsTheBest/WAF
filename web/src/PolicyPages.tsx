import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Collapse,
  Drawer,
  Col,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import {
  PlusOutlined,
  DeleteOutlined,
  EditOutlined,
  ExperimentOutlined,
} from "@ant-design/icons";
import { actionColor, api, ruleActionOptions } from "./api";
import {
  defaultChallenge,
  defaultRoute,
  defaultSite,
  isChallengeAction,
} from "./types";
import type {
  CustomRule,
  Exclusion,
  ManagedRule,
  RateLimit,
  RoutePolicy,
  Site,
} from "./types";
const { Text, Paragraph } = Typography;
export interface PolicyProps {
  sites: Site[];
  selected: string;
  select: (id: string) => void;
  change: (sites: Site[]) => void;
  editable: boolean;
}
function SitePick(p: PolicyProps) {
  return (
    <Select
      aria-label="选择站点"
      placeholder="选择站点"
      value={p.selected || undefined}
      onChange={p.select}
      className="site-select"
      options={p.sites.map((s) => ({ value: s.id, label: s.name || s.id }))}
    />
  );
}
function useSite(p: PolicyProps) {
  const site = p.sites.find((s) => s.id === p.selected);
  const update = (next: Site) =>
    p.change(p.sites.map((s) => (s.id === next.id ? next : s)));
  return { site, update };
}
const empty = <Empty description="请先添加并选择一个站点" />;
const idRules = [
  { required: true, message: "请输入标识" },
  {
    pattern: /^[A-Za-z0-9_-]{1,64}$/,
    message: "使用字母、数字、下划线或连字符，最多 64 字符",
  },
];
export function SitesPage(p: PolicyProps) {
  const [editing, setEditing] = useState<Site | null>(null);
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();
  const edit = (site?: Site) => {
    setEditing(site || null);
    form.setFieldsValue(site ? structuredClone(site) : defaultSite());
    setOpen(true);
  };
  const save = async () => {
    const values = await form.validateFields();
    const site = { ...(editing || defaultSite()), ...values } as Site;
    site.domains = site.domains.map((s) => s.trim().toLowerCase());
    if (!site.https) site.redirect_http = false;
    if (!editing && p.sites.some((s) => s.id === site.id)) {
      message.error("站点标识已存在");
      return;
    }
    p.change(
      editing
        ? p.sites.map((s) => (s.id === editing.id ? site : s))
        : [...p.sites, site],
    );
    p.select(site.id);
    setOpen(false);
  };
  return (
    <>
      <Card
        title="站点列表"
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined aria-hidden="true" />}
            disabled={!p.editable}
            onClick={() => edit()}
          >
            添加站点
          </Button>
        }
      >
        <Table
          dataSource={p.sites}
          rowKey="id"
          pagination={false}
          scroll={{ x: 800 }}
          columns={[
            {
              title: "站点",
              render: (_, s: Site) => (
                <Space orientation="vertical" size={0}>
                  <Text strong>{s.name || s.id}</Text>
                  <Text type="secondary">{s.id}</Text>
                </Space>
              ),
            },
            {
              title: "域名",
              render: (_, s: Site) =>
                s.domains.map((d) => <Tag key={d}>{d}</Tag>),
            },
            {
              title: "状态",
              render: (_, s: Site) => (
                <Tag color={s.enabled ? "success" : "default"}>
                  {s.enabled ? "已启用" : "已停用"}
                </Tag>
              ),
            },
            {
              title: "连接",
              render: (_, s: Site) => (
                <Tag color={s.https ? "blue" : "default"}>
                  {s.https ? "HTTPS · HTTP/2" : "HTTP"}
                </Tag>
              ),
            },
            {
              title: "托管防护",
              render: (_, s: Site) => (
                <Tag color={s.managed.mode === "block" ? "success" : "warning"}>
                  {
                    { block: "拦截", observe: "观察", off: "关闭" }[
                      s.managed.mode
                    ]
                  }
                </Tag>
              ),
            },
            { title: "上游", render: (_, s: Site) => s.upstreams.length },
            {
              title: "操作",
              render: (_, s: Site) => (
                <Space>
                  <Button
                    size="small"
                    icon={<EditOutlined aria-hidden="true" />}
                    disabled={!p.editable}
                    onClick={() => edit(s)}
                  >
                    编辑
                  </Button>
                  <Popconfirm
                    title="从草稿移除此站点？发布后停止转发。"
                    onConfirm={() =>
                      p.change(p.sites.filter((x) => x.id !== s.id))
                    }
                  >
                    <Button size="small" danger disabled={!p.editable}>
                      移除
                    </Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>
      <Modal
        title={editing ? "编辑站点" : "添加站点"}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        width={850}
        okText="保存到草稿"
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          onValuesChange={(v) => {
            if (v.https === false) form.setFieldValue("redirect_http", false);
          }}
        >
          <Row gutter={20}>
            <Col xs={24} md={12}>
              <Form.Item name="id" label="站点标识" rules={idRules}>
                <Input disabled={!!editing} placeholder="main-site" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="name"
                label="显示名称"
                rules={[{ required: true }]}
              >
                <Input placeholder="主站" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="domains"
            label="域名"
            rules={[{ required: true }]}
            extra="支持 *.example.com，不可使用管理后台域名。"
          >
            <Select
              mode="tags"
              tokenSeparators={[",", " "]}
              placeholder="example.com"
            />
          </Form.Item>
          <Row gutter={20}>
            <Col xs={24} md={8}>
              <Form.Item
                name="enabled"
                label="启用站点"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name="https"
                label="自动 HTTPS"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name="redirect_http"
                label="HTTP 跳转 HTTPS"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="dns_credential" label="Cloudflare 凭据名称">
            <Input placeholder="cloudflare" />
          </Form.Item>
          <Form.List name="upstreams">
            {(fields, { add, remove }) => (
              <>
                <div className="form-heading">
                  回源地址{" "}
                  <Text type="secondary">
                    HTTPS 回源会校验证书，健康检查不跟随重定向。
                  </Text>
                </div>
                {fields.map((f) => (
                  <Row gutter={12} key={f.key} align="middle">
                    <Col xs={24} md={12}>
                      <Form.Item
                        name={[f.name, "url"]}
                        label="上游 URL"
                        rules={[{ required: true }]}
                      >
                        <Input placeholder="http://127.0.0.1:3000" />
                      </Form.Item>
                    </Col>
                    <Col xs={24} md={4}>
                      <Form.Item name={[f.name, "weight"]} label="权重">
                        <InputNumber min={1} max={100} />
                      </Form.Item>
                    </Col>
                    <Col xs={24} md={6}>
                      <Form.Item
                        name={[f.name, "health_path"]}
                        label="健康检查路径"
                      >
                        <Input placeholder="/health（留空关闭）" />
                      </Form.Item>
                    </Col>
                    <Col xs={24} md={2}>
                      <Button
                        aria-label="删除上游"
                        icon={<DeleteOutlined aria-hidden="true" />}
                        disabled={fields.length === 1}
                        onClick={() => remove(f.name)}
                      />
                    </Col>
                  </Row>
                ))}
                <Button
                  icon={<PlusOutlined aria-hidden="true" />}
                  onClick={() => add({ url: "", weight: 1, health_path: "" })}
                >
                  添加上游
                </Button>
              </>
            )}
          </Form.List>
          <Row gutter={20} className="form-top">
            <Col xs={24} md={10}>
              <Form.Item
                name="max_connections_per_ip"
                label="每个 IP 的 WebSocket 连接上限"
              >
                <InputNumber min={1} max={8192} />
              </Form.Item>
            </Col>
            <Col xs={24} md={14}>
              <Form.Item
                name="websocket_origins"
                label="允许的 WebSocket Origin"
                extra="留空时只允许同源浏览器；不带 Origin 的客户端仍受规则和限流控制。"
              >
                <Select mode="tags" placeholder="https://example.com" />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>
    </>
  );
}
export function SecurityRulesPage(
  p: PolicyProps & { managedRequest: number; onManagedClose: () => void },
) {
  const { site } = useSite(p);
  const [managedOpen, setManagedOpen] = useState(false);
  useEffect(() => {
    if (p.managedRequest > 0) setManagedOpen(true);
  }, [p.managedRequest]);
  return (
    <Space
      orientation="vertical"
      size={20}
      className="full-width security-rules"
    >
      <Card>
        <div className="security-rules-heading">
          <div>
            <Text strong>统一管理站点防护</Text>
            <Paragraph type="secondary">
              按自定义规则、速率限制规则、托管规则的顺序执行。修改保存到草稿，发布后生效。
            </Paragraph>
          </div>
          <SitePick {...p} />
        </div>
        {site && (
          <Space wrap>
            <Tag>
              自定义规则 {site.rules.filter((r) => r.enabled).length} /{" "}
              {site.rules.length}
            </Tag>
            <Tag>
              速率限制规则 {site.rate_limits.filter((r) => r.enabled).length} /{" "}
              {site.rate_limits.length}
            </Tag>
            <Tag>托管规则 · OWASP CRS</Tag>
          </Space>
        )}
      </Card>
      {site ? (
        <>
          <section aria-label="自定义规则">
            <CustomPage {...p} />
          </section>
          <section aria-label="速率限制规则">
            <RatePage {...p} />
          </section>
          <section aria-label="托管规则">
            <Card
              title="托管规则"
              extra={
                <Button onClick={() => setManagedOpen(true)}>
                  配置托管规则
                </Button>
              }
            >
              <Space orientation="vertical" size={12}>
                <Space wrap>
                  <Text strong>OWASP Core Rule Set</Text>
                  <Tag
                    color={
                      site.managed.mode === "block"
                        ? "green"
                        : site.managed.mode === "observe"
                          ? "orange"
                          : "default"
                    }
                  >
                    {site.managed.mode === "block"
                      ? "拦截"
                      : site.managed.mode === "observe"
                        ? "观察"
                        : "关闭"}
                  </Tag>
                </Space>
                <Text type="secondary">
                  检测 SQL 注入、跨站脚本等常见攻击。新站点默认观察模式。
                </Text>
                <Space wrap>
                  <Tag>敏感等级 PL{site.managed.paranoia}</Tag>
                  <Tag>异常分数阈值 {site.managed.threshold}</Tag>
                  <Tag>规则例外 {site.managed.exclusions.length}</Tag>
                </Space>
              </Space>
            </Card>
          </section>
          <Drawer
            title="配置托管规则"
            open={managedOpen}
            size={1000}
            destroyOnHidden
            onClose={() => {
              setManagedOpen(false);
              p.onManagedClose();
            }}
          >
            <ManagedPage {...p} />
          </Drawer>
        </>
      ) : (
        empty
      )}
    </Space>
  );
}

export function ManagedPage(p: PolicyProps) {
  const { site, update } = useSite(p);
  const [rules, setRules] = useState<ManagedRule[]>([]);
  const [search, setSearch] = useState("");
  const [group, setGroup] = useState<string>();
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();
  useEffect(() => {
    api<{ rules: ManagedRule[] }>("/rules/catalog")
      .then((r) => setRules(r.rules))
      .catch((e) => message.error(e.message));
  }, []);
  const excluded = new Set(
    site?.managed.exclusions
      .filter((x) => !x.path_prefix && !x.target)
      .map((x) => x.rule_id),
  );
  const setExclusions = (exclusions: Exclusion[]) => {
    if (site) update({ ...site, managed: { ...site.managed, exclusions } });
  };
  const addExclusion = async () => {
    const value = await form.validateFields();
    setExclusions([
      ...(site?.managed.exclusions || []),
      {
        rule_id: value.rule_id,
        path_prefix: value.path_prefix || "",
        target: value.target || "",
      },
    ]);
    setOpen(false);
  };
  const filtered = rules.filter(
    (r) =>
      (!group || r.group === group) &&
      `${r.id} ${r.message} ${r.tags.join(" ")}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  return (
    <Space orientation="vertical" size={20} className="full-width">
      <Card title="OWASP CRS 设置">
        {site ? (
          <>
            <Alert
              type={site.managed.mode === "block" ? "success" : "warning"}
              showIcon
              title={
                site.managed.mode === "block"
                  ? "拦截模式：命中阈值时拒绝请求"
                  : "观察或关闭模式不会执行托管规则拦截"
              }
              description="新站点默认观察模式。发现误报时，可按路径或参数添加例外；规则集随软件更新。"
            />
            <Row gutter={[24, 16]} className="form-top">
              <Col xs={24} md={12}>
                <Text strong>运行模式</Text>
                <div className="form-top">
                  <Radio.Group
                    disabled={!p.editable}
                    value={site.managed.mode}
                    onChange={(e) =>
                      update({
                        ...site,
                        managed: { ...site.managed, mode: e.target.value },
                      })
                    }
                    options={[
                      { label: "观察", value: "observe" },
                      { label: "拦截", value: "block" },
                      { label: "关闭", value: "off" },
                    ]}
                  />
                </div>
              </Col>
              <Col xs={24} md={6}>
                <Text strong>敏感等级</Text>
                <div className="form-top">
                  <Select
                    disabled={!p.editable}
                    value={site.managed.paranoia}
                    onChange={(v) =>
                      update({
                        ...site,
                        managed: { ...site.managed, paranoia: v },
                      })
                    }
                    options={[1, 2, 3, 4].map((v) => ({
                      value: v,
                      label: `PL${v}`,
                    }))}
                  />
                </div>
              </Col>
              <Col xs={24} md={6}>
                <Text strong>异常分数阈值</Text>
                <div className="form-top">
                  <InputNumber
                    disabled={!p.editable}
                    min={1}
                    max={100}
                    value={site.managed.threshold}
                    onChange={(v) =>
                      update({
                        ...site,
                        managed: { ...site.managed, threshold: v || 5 },
                      })
                    }
                  />
                </div>
              </Col>
            </Row>
          </>
        ) : (
          empty
        )}
      </Card>
      {site && (
        <>
          <Card
            title="规则目录"
            extra={
              <div className="filter-bar">
                <Select
                  allowClear
                  placeholder="全部分类"
                  value={group}
                  onChange={setGroup}
                  style={{ width: 260 }}
                  options={[...new Set(rules.map((r) => r.group))].map((g) => ({
                    value: g,
                    label: g,
                  }))}
                />
                <Input.Search
                  placeholder="规则 ID、说明或标签"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  style={{ width: 240 }}
                />
              </div>
            }
          >
            <Table
              rowKey="id"
              size="small"
              dataSource={filtered}
              pagination={{ pageSize: 15, showSizeChanger: false }}
              scroll={{ x: 750 }}
              columns={[
                { title: "ID", dataIndex: "id", width: 95 },
                {
                  title: "检测说明",
                  render: (_, r: ManagedRule) => (
                    <Space orientation="vertical" size={2}>
                      <span>{r.message || r.group}</span>
                      <Text type="secondary" className="small">
                        {r.group}
                      </Text>
                    </Space>
                  ),
                },
                {
                  title: "等级",
                  render: (_, r: ManagedRule) => <Tag>PL{r.paranoia}</Tag>,
                  width: 75,
                },
                {
                  title: "全局启用",
                  width: 100,
                  render: (_, r: ManagedRule) => (
                    <Switch
                      size="small"
                      disabled={!p.editable || !r.tunable}
                      checked={!excluded.has(r.id)}
                      onChange={(on) =>
                        setExclusions(
                          on
                            ? site.managed.exclusions.filter(
                                (x) =>
                                  !(
                                    x.rule_id === r.id &&
                                    !x.path_prefix &&
                                    !x.target
                                  ),
                              )
                            : [
                                ...site.managed.exclusions,
                                { rule_id: r.id, path_prefix: "", target: "" },
                              ],
                        )
                      }
                    />
                  ),
                },
              ]}
            />
          </Card>
          <Card
            title="规则例外"
            extra={
              <Button
                disabled={!p.editable}
                icon={<PlusOutlined aria-hidden="true" />}
                onClick={() => {
                  form.resetFields();
                  setOpen(true);
                }}
              >
                添加例外
              </Button>
            }
          >
            <Table
              rowKey={(_, i) => String(i)}
              dataSource={site.managed.exclusions}
              pagination={{ pageSize: 10 }}
              scroll={{ x: 550 }}
              columns={[
                { title: "规则 ID", dataIndex: "rule_id" },
                {
                  title: "路径前缀",
                  render: (_, x: Exclusion) => x.path_prefix || "全部路径",
                },
                {
                  title: "限定参数",
                  render: (_, x: Exclusion) => x.target || "整条规则",
                },
                {
                  title: "操作",
                  render: (_, x: Exclusion, i: number) => (
                    <Button
                      danger
                      size="small"
                      disabled={!p.editable}
                      onClick={() =>
                        setExclusions(
                          site.managed.exclusions.filter((_, j) => i !== j),
                        )
                      }
                    >
                      移除
                    </Button>
                  ),
                },
              ]}
            />
          </Card>
        </>
      )}
      <Modal
        title="添加规则例外"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void addExclusion()}
        okText="加入草稿"
      >
        <Form name="managed-exclusion" form={form} layout="vertical">
          <Form.Item
            name="rule_id"
            label="规则 ID"
            rules={[{ required: true }]}
          >
            <Select
              showSearch
              optionFilterProp="label"
              options={rules
                .filter((r) => r.tunable)
                .map((r) => ({
                  value: r.id,
                  label: `${r.id} ${r.message}`,
                }))}
            />
          </Form.Item>
          <Form.Item name="path_prefix" label="路径前缀（留空适用于所有路径）">
            <Input placeholder="/api/comments" />
          </Form.Item>
          <Form.Item
            name="target"
            label="参数限定（留空跳过整条规则）"
            extra="例如 ARGS:message 或 REQUEST_HEADERS:User-Agent"
          >
            <Input placeholder="ARGS:message" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
export function CustomPage(p: PolicyProps) {
  const { site, update } = useSite(p);
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(-1);
  const [form] = Form.useForm();
  const [conditions, setConditions] = useState([
    { field: "request.path", op: "startsWith", value: "/admin" },
  ]);
  const [logic, setLogic] = useState("&&");
  const [checking, setChecking] = useState(false);
  const [sample, setSample] = useState(
    '{"client":{"ip":"192.0.2.1"},"request":{"method":"GET","path":"/admin","host":"example.com","headers":{},"query":{},"user_agent":"Mozilla/5.0","protocol":"HTTP/2.0","tls":true}}',
  );
  const openEditor = (r?: CustomRule, i = -1) => {
    setIndex(i);
    form.resetFields();
    form.setFieldsValue(
      r
        ? {
            ...structuredClone(r),
            challenge: r.challenge || defaultChallenge(),
          }
        : {
            id: "",
            name: "",
            enabled: true,
            challenge: defaultChallenge(),
            priority: 100,
            expression: 'request.path.startsWith("/admin")',
            action: "block",
            skip: [],
          },
    );
    setOpen(true);
  };
  const save = async () => {
    if (!site) return;
    const values = await form.validateFields();
    if (!isChallengeAction(values.action)) delete values.challenge;
    else values.challenge = { ...defaultChallenge(), ...values.challenge };
    if (values.action !== "skip") values.skip = [];
    const rules = [...site.rules];
    if (index < 0) {
      if (rules.some((r) => r.id === values.id)) {
        message.error("规则标识已存在");
        return;
      }
      rules.push(values);
    } else {
      rules[index] = values;
    }
    update({ ...site, rules });
    setOpen(false);
  };
  const generate = () => {
    const text = conditions
      .map((c) => {
        const value = JSON.stringify(c.value);
        if (c.op === "in_cidr") return `in_cidr(${c.field}, ${value})`;
        if (c.op === "eq") return `${c.field} == ${value}`;
        if (c.op === "ne") return `${c.field} != ${value}`;
        return `${c.field}.${c.op}(${value})`;
      })
      .map((c) => `(${c})`)
      .join(` ${logic} `);
    form.setFieldValue("expression", text);
  };
  const check = async () => {
    setChecking(true);
    try {
      const result = await api<{ matches: boolean }>(
        "/rules/evaluate",
        "POST",
        {
          expression: form.getFieldValue("expression"),
          sample: JSON.parse(sample),
        },
      );
      message.success(
        result.matches
          ? "表达式有效，样例请求匹配"
          : "表达式有效，样例请求不匹配",
      );
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setChecking(false);
    }
  };
  return (
    <>
      <Card
        title="自定义规则"
        extra={
          <Space wrap>
            <Button
              type="primary"
              icon={<PlusOutlined aria-hidden="true" />}
              disabled={!site || !p.editable}
              onClick={() => openEditor()}
            >
              添加自定义规则
            </Button>
          </Space>
        }
      >
        {site ? (
          <>
            <Paragraph type="secondary">
              优先级数值越小，规则越先执行。跳过操作只作用于所选检查，协议和资源限制仍然生效。
            </Paragraph>
            <Table
              dataSource={[...site.rules].sort(
                (a, b) => a.priority - b.priority,
              )}
              rowKey="id"
              pagination={false}
              scroll={{ x: 850 }}
              columns={[
                { title: "优先级", dataIndex: "priority", width: 80 },
                {
                  title: "名称",
                  render: (_, r: CustomRule) => (
                    <Space orientation="vertical" size={0}>
                      <Text strong>{r.name || r.id}</Text>
                      <Text type="secondary">{r.id}</Text>
                    </Space>
                  ),
                },
                {
                  title: "表达式",
                  render: (_, r: CustomRule) => (
                    <code className="expression-preview">{r.expression}</code>
                  ),
                },
                {
                  title: "动作",
                  dataIndex: "action",
                  render: (v: string) => (
                    <Tag color={actionColor[v]}>
                      {ruleActionOptions
                        .find((option) => option.value === v)
                        ?.label.split(" · ")[0] || v}
                    </Tag>
                  ),
                },
                {
                  title: "启用",
                  render: (_, r: CustomRule) => (
                    <Switch
                      size="small"
                      disabled={!p.editable}
                      checked={r.enabled}
                      onChange={(enabled) =>
                        update({
                          ...site,
                          rules: site.rules.map((x) =>
                            x.id === r.id ? { ...x, enabled } : x,
                          ),
                        })
                      }
                    />
                  ),
                },
                {
                  title: "操作",
                  render: (_, r: CustomRule) => (
                    <Space>
                      <Button
                        size="small"
                        disabled={!p.editable}
                        onClick={() =>
                          openEditor(
                            r,
                            site.rules.findIndex((x) => x.id === r.id),
                          )
                        }
                      >
                        编辑
                      </Button>
                      <Popconfirm
                        title="移除此规则？"
                        onConfirm={() =>
                          update({
                            ...site,
                            rules: site.rules.filter((x) => x.id !== r.id),
                          })
                        }
                      >
                        <Button danger size="small" disabled={!p.editable}>
                          移除
                        </Button>
                      </Popconfirm>
                    </Space>
                  ),
                },
              ]}
            />
          </>
        ) : (
          empty
        )}
      </Card>
      <Modal
        title="自定义规则"
        open={open}
        width={900}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        okText="保存到草稿"
      >
        <Form name="custom-rule" form={form} layout="vertical">
          <Row gutter={20}>
            <Col xs={24} md={8}>
              <Form.Item name="id" label="规则标识" rules={idRules}>
                <Input disabled={index >= 0} />
              </Form.Item>
            </Col>
            <Col xs={24} md={10}>
              <Form.Item name="name" label="显示名称">
                <Input />
              </Form.Item>
            </Col>
            <Col xs={24} md={6}>
              <Form.Item name="priority" label="优先级">
                <InputNumber min={0} max={100000} />
              </Form.Item>
            </Col>
          </Row>
          <Card
            size="small"
            title="条件构建器"
            extra={
              <Select
                value={logic}
                onChange={setLogic}
                options={[
                  { value: "&&", label: "全部满足" },
                  { value: "||", label: "任意满足" },
                ]}
              />
            }
          >
            {conditions.map((c, i) => (
              <Row gutter={[8, 8]} key={i} className="condition-row">
                <Col xs={24} md={8}>
                  <Select
                    className="full-width"
                    value={c.field}
                    onChange={(field) =>
                      setConditions(
                        conditions.map((x, j) =>
                          i === j ? { ...x, field } : x,
                        ),
                      )
                    }
                    options={[
                      "client.ip",
                      "request.host",
                      "request.method",
                      "request.path",
                      "request.user_agent",
                      "request.protocol",
                    ].map((x) => ({ value: x, label: x }))}
                  />
                </Col>
                <Col xs={24} md={6}>
                  <Select
                    className="full-width"
                    value={c.op}
                    onChange={(op) =>
                      setConditions(
                        conditions.map((x, j) => (i === j ? { ...x, op } : x)),
                      )
                    }
                    options={[
                      ["eq", "等于"],
                      ["ne", "不等于"],
                      ["contains", "包含"],
                      ["startsWith", "开头是"],
                      ["matches", "正则匹配"],
                      ["in_cidr", "属于 CIDR"],
                    ].map(([value, label]) => ({ value, label }))}
                  />
                </Col>
                <Col xs={24} md={8}>
                  <Input
                    value={c.value}
                    onChange={(e) =>
                      setConditions(
                        conditions.map((x, j) =>
                          i === j ? { ...x, value: e.target.value } : x,
                        ),
                      )
                    }
                  />
                </Col>
                <Col xs={24} md={2}>
                  <Button
                    icon={<DeleteOutlined aria-hidden="true" />}
                    aria-label="删除条件"
                    disabled={conditions.length === 1}
                    onClick={() =>
                      setConditions(conditions.filter((_, j) => i !== j))
                    }
                  />
                </Col>
              </Row>
            ))}
            <Space>
              <Button
                size="small"
                onClick={() =>
                  setConditions([
                    ...conditions,
                    { field: "request.method", op: "eq", value: "GET" },
                  ])
                }
              >
                添加条件
              </Button>
              <Button size="small" onClick={generate}>
                生成表达式
              </Button>
            </Space>
          </Card>
          <Form.Item
            name="expression"
            label="CEL 表达式"
            className="form-top"
            rules={[{ required: true }]}
            extra={
              '请求头和查询参数是多值映射。示例："x-key" in request.headers && request.headers["x-key"].exists(v, v == "demo")'
            }
          >
            <Input.TextArea rows={4} className="code-input" />
          </Form.Item>
          <Row gutter={20}>
            <Col xs={24} md={12}>
              <Form.Item name="action" label="动作">
                <Select
                  virtual={false}
                  options={ruleActionOptions}
                  onChange={(action) => {
                    if (
                      isChallengeAction(action) &&
                      !form.getFieldValue("challenge")
                    )
                      form.setFieldValue("challenge", defaultChallenge());
                  }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="enabled" label="启用" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item noStyle shouldUpdate={(p, c) => p.action !== c.action}>
            {({ getFieldValue }) =>
              getFieldValue("action") === "skip" ? (
                <Form.Item
                  name="skip"
                  label="跳过哪些检查"
                  rules={[{ required: true }]}
                >
                  <Select
                    mode="multiple"
                    options={[
                      { value: "custom_rules", label: "剩余自定义规则" },
                      { value: "rate_limits", label: "全部速率限制规则" },
                      { value: "managed", label: "托管规则" },
                      ...(site?.rate_limits || []).map((r) => ({
                        value: `rate:${r.id}`,
                        label: `限流 ${r.name || r.id}`,
                      })),
                      ...(site?.rules || [])
                        .filter((r) => r.id !== getFieldValue("id"))
                        .map((r) => ({
                          value: `rule:${r.id}`,
                          label: `自定义规则 ${r.name || r.id}`,
                        })),
                    ]}
                  />
                </Form.Item>
              ) : null
            }
          </Form.Item>
          <Form.Item
            noStyle
            shouldUpdate={(previous, current) =>
              previous.action !== current.action
            }
          >
            {({ getFieldValue }) =>
              isChallengeAction(getFieldValue("action")) ? (
                <>
                  <Alert
                    className="form-top"
                    showIcon
                    type="info"
                    title={
                      getFieldValue("action") === "managed_challenge"
                        ? "根据请求频率与验证失败记录，自动选择验证方式"
                        : getFieldValue("action") === "interactive_challenge"
                          ? "访客点击复选框后开始验证"
                          : "浏览器自动完成验证"
                    }
                    description="浏览器页面通过验证后返回原地址；API、上传和流式请求由调用方重试。每条规则的通行有效期独立计算。"
                  />
                  <Collapse
                    className="form-top"
                    items={[
                      {
                        key: "challenge-options",
                        label: "质询高级设置",
                        forceRender: true,
                        children: (
                          <Row gutter={20}>
                            <Col xs={24} md={12}>
                              <Form.Item
                                name={["challenge", "work_factor"]}
                                label="计算强度"
                                initialValue={5000}
                                extra="默认 5000，数值越高，访客验证耗时越长。"
                                rules={[
                                  {
                                    required: true,
                                    type: "integer",
                                    min: 1000,
                                    max: 20000,
                                  },
                                ]}
                              >
                                <InputNumber
                                  min={1000}
                                  max={20000}
                                  step={1000}
                                />
                              </Form.Item>
                            </Col>
                            <Col xs={24} md={12}>
                              <Form.Item
                                name={["challenge", "clearance_seconds"]}
                                label="通行有效期（秒）"
                                initialValue={1800}
                                rules={[
                                  {
                                    required: true,
                                    type: "integer",
                                    min: 60,
                                    max: 86400,
                                  },
                                ]}
                              >
                                <InputNumber min={60} max={86400} />
                              </Form.Item>
                            </Col>
                          </Row>
                        ),
                      },
                    ]}
                  />
                </>
              ) : null
            }
          </Form.Item>
          <Card size="small" title="样例验证">
            <Input.TextArea
              value={sample}
              onChange={(e) => setSample(e.target.value)}
              rows={4}
              className="code-input"
            />
            <Button
              icon={<ExperimentOutlined aria-hidden="true" />}
              loading={checking}
              onClick={() => void check()}
              className="form-top"
            >
              校验并运行样例
            </Button>
          </Card>
        </Form>
      </Modal>
    </>
  );
}
export function RatePage(p: PolicyProps) {
  const { site, update } = useSite(p);
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(-1);
  const [form] = Form.useForm();
  const edit = (r?: RateLimit, i = -1) => {
    setIndex(i);
    form.setFieldsValue(
      r
        ? structuredClone(r)
        : {
            id: "",
            name: "",
            enabled: true,
            expression: "true",
            key: "ip",
            requests_per_second: 10,
            burst: 20,
            ban_seconds: 0,
          },
    );
    setOpen(true);
  };
  const save = async () => {
    if (!site) return;
    const v = await form.validateFields();
    const rules = [...site.rate_limits];
    if (index < 0) rules.push(v);
    else rules[index] = v;
    update({ ...site, rate_limits: rules });
    setOpen(false);
  };
  return (
    <>
      <Card
        title="速率限制规则"
        extra={
          <Space wrap>
            <Button
              type="primary"
              icon={<PlusOutlined aria-hidden="true" />}
              disabled={!site || !p.editable}
              onClick={() => edit()}
            >
              添加速率限制规则
            </Button>
          </Space>
        }
      >
        {site ? (
          <Table
            rowKey="id"
            dataSource={site.rate_limits}
            pagination={false}
            scroll={{ x: 800 }}
            columns={[
              { title: "策略", render: (_, r: RateLimit) => r.name || r.id },
              {
                title: "匹配条件",
                dataIndex: "expression",
                render: (s: string) => <code>{s}</code>,
              },
              { title: "维度", dataIndex: "key" },
              {
                title: "速率 / 突发",
                render: (_, r: RateLimit) =>
                  `${r.requests_per_second}/秒 · ${r.burst}`,
              },
              {
                title: "封禁",
                render: (_, r: RateLimit) =>
                  r.ban_seconds ? `${r.ban_seconds} 秒` : "仅限流",
              },
              {
                title: "启用",
                render: (_, r: RateLimit) => (
                  <Switch
                    size="small"
                    disabled={!p.editable}
                    checked={r.enabled}
                    onChange={(enabled) =>
                      update({
                        ...site,
                        rate_limits: site.rate_limits.map((x) =>
                          x.id === r.id ? { ...x, enabled } : x,
                        ),
                      })
                    }
                  />
                ),
              },
              {
                title: "操作",
                render: (_, r: RateLimit, i: number) => (
                  <Space>
                    <Button
                      size="small"
                      disabled={!p.editable}
                      onClick={() => edit(r, i)}
                    >
                      编辑
                    </Button>
                    <Button
                      size="small"
                      danger
                      disabled={!p.editable}
                      onClick={() =>
                        update({
                          ...site,
                          rate_limits: site.rate_limits.filter(
                            (_, j) => i !== j,
                          ),
                        })
                      }
                    >
                      移除
                    </Button>
                  </Space>
                ),
              },
            ]}
          />
        ) : (
          empty
        )}
      </Card>
      <Modal
        title="速率限制规则"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        okText="保存到草稿"
      >
        <Form name="rate-rule" form={form} layout="vertical">
          <Form.Item name="id" label="策略标识" rules={idRules}>
            <Input disabled={index >= 0} />
          </Form.Item>
          <Form.Item name="name" label="显示名称">
            <Input />
          </Form.Item>
          <Form.Item
            name="expression"
            label="CEL 匹配条件"
            rules={[{ required: true }]}
          >
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item name="key" label="限流维度">
            <Select
              options={[
                { value: "ip", label: "每个 IP" },
                { value: "site", label: "整个站点" },
                { value: "ip_path", label: "每个 IP + 路径" },
              ]}
            />
          </Form.Item>
          <Row gutter={20}>
            <Col xs={24} md={12}>
              <Form.Item name="requests_per_second" label="每秒请求数">
                <InputNumber min={0.01} max={100000} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="burst" label="突发容量">
                <InputNumber min={1} max={100000} />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="ban_seconds"
            label="超限后封禁秒数（0 为仅返回 429）"
          >
            <InputNumber min={0} max={86400} />
          </Form.Item>
          <Form.Item name="enabled" valuePropName="checked" label="启用">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
export function RoutesPage(p: PolicyProps) {
  const { site, update } = useSite(p);
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(-1);
  const [form] = Form.useForm();
  const edit = (r?: RoutePolicy, i = -1) => {
    setIndex(i);
    const v = r || defaultRoute();
    form.setFieldsValue({ ...v, max_body_mib: v.max_body_bytes / 1024 / 1024 });
    setOpen(true);
  };
  const save = async () => {
    if (!site) return;
    const v = await form.validateFields();
    const route = {
      ...v,
      max_body_bytes: Math.round(v.max_body_mib * 1024 * 1024),
    };
    delete route.max_body_mib;
    const routes = [...site.routes];
    if (index < 0) routes.push(route);
    else routes[index] = route;
    update({ ...site, routes });
    setOpen(false);
  };
  return (
    <Space orientation="vertical" size={20} className="full-width">
      <Alert
        type="warning"
        showIcon
        title="流式上传不检查完整正文"
        description="启用后，请求正文边接收边转发，仅检查请求头。SSE 可继续使用完整正文检查。"
      />
      <Card
        title="路径与流式策略"
        extra={
          <Space wrap>
            <SitePick {...p} />
            <Button
              icon={<PlusOutlined aria-hidden="true" />}
              type="primary"
              disabled={!site || !p.editable}
              onClick={() => edit()}
            >
              添加路径
            </Button>
          </Space>
        }
      >
        {site ? (
          <Table
            rowKey={(_, i) => String(i)}
            dataSource={site.routes}
            pagination={false}
            scroll={{ x: 850 }}
            columns={[
              { title: "路径前缀", dataIndex: "path_prefix" },
              {
                title: "方法",
                render: (_, r: RoutePolicy) => r.methods?.join(", ") || "全部",
              },
              {
                title: "正文检查",
                render: (_, r: RoutePolicy) => (
                  <Tag color={r.body_mode === "stream" ? "orange" : "green"}>
                    {r.body_mode === "stream" ? "流式 · 仅请求头" : "完整检查"}
                  </Tag>
                ),
              },
              {
                title: "正文上限",
                render: (_, r: RoutePolicy) =>
                  `${r.max_body_bytes / 1024 / 1024} MiB`,
              },
              {
                title: "空闲 / 总时长",
                render: (_, r: RoutePolicy) =>
                  `${r.idle_timeout_seconds}s / ${r.max_duration_seconds || "不限"}`,
              },
              { title: "并发", dataIndex: "max_concurrent" },
              {
                title: "操作",
                render: (_, r: RoutePolicy, i: number) => (
                  <Space>
                    <Button
                      size="small"
                      disabled={!p.editable}
                      onClick={() => edit(r, i)}
                    >
                      编辑
                    </Button>
                    <Button
                      size="small"
                      danger
                      disabled={!p.editable}
                      onClick={() =>
                        update({
                          ...site,
                          routes: site.routes.filter((_, j) => i !== j),
                        })
                      }
                    >
                      移除
                    </Button>
                  </Space>
                ),
              },
            ]}
          />
        ) : (
          empty
        )}
      </Card>
      <Modal
        title="路径策略"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        okText="保存到草稿"
      >
        <Form name="route-policy" form={form} layout="vertical">
          <Form.Item
            name="path_prefix"
            label="路径前缀"
            rules={[{ required: true }]}
            extra="优先匹配最长前缀。未匹配时完整检查正文，上限 8 MiB。"
          >
            <Input placeholder="/upload/" />
          </Form.Item>
          <Form.Item name="methods" label="HTTP 方法（留空为全部）">
            <Select
              mode="multiple"
              options={[
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
              ].map((value) => ({ value, label: value }))}
            />
          </Form.Item>
          <Form.Item name="body_mode" label="正文处理">
            <Radio.Group
              options={[
                { value: "inspect", label: "完整检查" },
                { value: "stream", label: "流式上传" },
              ]}
            />
          </Form.Item>
          <Row gutter={20}>
            <Col xs={24} md={12}>
              <Form.Item
                name="max_body_mib"
                label="最大正文（MiB）"
                rules={[{ required: true }]}
              >
                <InputNumber min={0.001} max={1048576} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="max_concurrent" label="最大并发">
                <InputNumber min={1} max={8192} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="idle_timeout_seconds" label="空闲超时（秒）">
                <InputNumber min={1} max={86400} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="max_duration_seconds"
                label="总时长上限（秒）"
                extra="流式上传必须大于 0。"
              >
                <InputNumber min={0} max={86400} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>
    </Space>
  );
}
