let csrf = "";
export const setCSRF = (value: string) => {
  csrf = value;
};
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch("/api/v1" + path, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const content = await response
    .json()
    .catch(() => ({ error: `HTTP ${response.status}` }));
  if (!response.ok) {
    if (response.status === 401 && path != "/auth/login")
      window.dispatchEvent(new Event("session-expired"));
    throw new Error(content.error || `HTTP ${response.status}`);
  }
  return content as T;
}
export const timestamp = (s?: string) =>
  s ? new Date(s).toLocaleString("zh-CN") : "—";
export const actionNames: Record<string, string> = {
  allow: "放行",
  block: "拦截",
  observe: "观察命中",
  log: "记录",
  challenge: "浏览器挑战",
  rate_limit: "限流",
  resource_limit: "资源限制",
  error: "故障",
  cancelled: "客户端取消",
  redirect: "HTTPS 跳转",
};
export const actionColor: Record<string, string> = {
  allow: "success",
  block: "error",
  observe: "warning",
  log: "blue",
  challenge: "purple",
  rate_limit: "orange",
  resource_limit: "volcano",
  error: "error",
  cancelled: "default",
  redirect: "cyan",
};
