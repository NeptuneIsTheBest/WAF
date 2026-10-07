import { useState } from "react";
import {
  Button,
  Card,
  Col,
  Form,
  Input,
  Radio,
  Row,
  Select,
  Space,
  Tag,
  message,
} from "antd";
import type { FormInstance } from "antd";
import { DeleteOutlined, ExperimentOutlined } from "@ant-design/icons";
import { api } from "./api";
import type { Scope, Site } from "./types";

export function ScopeLabel({ scope, sites }: { scope: Scope; sites: Site[] }) {
  return scope.mode === "all" ? (
    <Tag>所有网站</Tag>
  ) : (
    <Space wrap size={4}>
      {scope.site_ids.map((id) => (
        <Tag key={id}>{sites.find((s) => s.id === id)?.name || id}</Tag>
      ))}
    </Space>
  );
}
export function ScopeFields({ sites }: { sites: Site[] }) {
  return (
    <>
      <Form.Item
        name={["scope", "mode"]}
        label="适用网站"
        rules={[{ required: true }]}
      >
        <Radio.Group
          options={[
            { value: "all", label: "所有网站（含新增网站）" },
            { value: "sites", label: "指定网站" },
          ]}
        />
      </Form.Item>
      <Form.Item
        noStyle
        shouldUpdate={(a, b) => a.scope?.mode !== b.scope?.mode}
      >
        {({ getFieldValue }) =>
          getFieldValue(["scope", "mode"]) === "sites" ? (
            <Form.Item
              name={["scope", "site_ids"]}
              label="选择适用网站"
              rules={[
                {
                  required: true,
                  type: "array",
                  min: 1,
                  message: "至少选择一个网站",
                },
              ]}
            >
              <Select
                mode="multiple"
                optionFilterProp="label"
                options={sites.map((s) => ({
                  value: s.id,
                  label: s.name || s.id,
                }))}
              />
            </Form.Item>
          ) : null
        }
      </Form.Item>
    </>
  );
}
// Clear hidden selections only when saving; switching tabs must not widen a scope.
export function cleanScope(scope: Scope): Scope {
  return {
    mode: scope.mode,
    site_ids: scope.mode === "all" ? [] : scope.site_ids || [],
  };
}
export function MatchFields({
  sites,
  form,
}: {
  sites: Site[];
  form: FormInstance;
}) {
  const [conditions, setConditions] = useState([
    { field: "request.host", op: "eq", value: "example.com" },
  ]);
  const [logic, setLogic] = useState("&&");
  const [checking, setChecking] = useState(false);
  const [sample, setSample] = useState(
    JSON.stringify({
      site: { id: sites[0]?.id || "example" },
      client: { ip: "192.0.2.1" },
      request: {
        host: sites[0]?.domains[0] || "example.com",
        path: "/admin",
        method: "GET",
        headers: {},
        query: {},
        user_agent: "Mozilla/5.0",
        protocol: "HTTP/2.0",
        tls: true,
      },
    }),
  );
  const generate = () =>
    form.setFieldValue(
      "expression",
      conditions
        .map((c) => {
          const value = JSON.stringify(c.value);
          if (c.op === "in_cidr") return `in_cidr(${c.field}, ${value})`;
          if (c.op === "eq") return `${c.field} == ${value}`;
          if (c.op === "ne") return `${c.field} != ${value}`;
          return `${c.field}.${c.op}(${value})`;
        })
        .map((c) => `(${c})`)
        .join(` ${logic} `),
    );
  const check = async () => {
    setChecking(true);
    try {
      await form.validateFields([
        "expression",
        ["scope", "mode"],
        ["scope", "site_ids"],
      ]);
      const r = await api<{ matches: boolean }>("/rules/evaluate", "POST", {
        expression: form.getFieldValue("expression"),
        scope: cleanScope(form.getFieldValue("scope")),
        sample: JSON.parse(sample),
      });
      message.success(
        r.matches ? "规则有效，样例请求匹配" : "规则有效，样例请求不匹配",
      );
    } catch (e) {
      if (e instanceof Error) message.error(e.message);
    } finally {
      setChecking(false);
    }
  };
  return (
    <>
      <ScopeFields sites={sites} />
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
                    conditions.map((x, j) => (i === j ? { ...x, field } : x)),
                  )
                }
                options={[
                  "site.id",
                  "client.ip",
                  "request.host",
                  "request.method",
                  "request.path",
                  "request.user_agent",
                  "request.protocol",
                ].map((value) => ({ value, label: value }))}
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
                aria-label={`条件值 ${i + 1}`}
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
                icon={<DeleteOutlined />}
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
                { field: "request.path", op: "startsWith", value: "/api" },
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
          '网站范围与表达式需同时满足。true 匹配范围内所有请求；域名示例：request.host == "example.com"'
        }
      >
        <Input.TextArea rows={3} className="code-input" />
      </Form.Item>
      <Card size="small" title="样例验证" className="form-bottom">
        <Input.TextArea
          aria-label="样例请求"
          value={sample}
          onChange={(e) => setSample(e.target.value)}
          rows={4}
          className="code-input"
        />
        <Button
          icon={<ExperimentOutlined />}
          loading={checking}
          onClick={() => void check()}
          className="form-top"
        >
          校验并运行样例
        </Button>
      </Card>
    </>
  );
}
