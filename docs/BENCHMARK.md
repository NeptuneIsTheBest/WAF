# 容量验收

目标基准环境为 4 vCPU、4 GiB Linux。当前项目中的容量工具用于获得可复现数据，不预先保证某个 RPS。

构建工具与本地模拟上游：

```sh
go build -o bin/wafbench ./cmd/wafbench
go build -o bin/waforigin ./cmd/waforigin
./bin/waforigin --listen 127.0.0.1:18081
./bin/wafbench --config-out /tmp/waf-benchmark.json --sites 50
```

生成配置包含 50 个 `bench-01.localhost` 到 `bench-50.localhost` 站点，CRS PL1 拦截模式，每站点 10 条自定义规则。通过管理 API 将 bundle 放入草稿并发布；不要覆盖真实业务环境。管理 API 使用 `/auth/session` 返回的 CSRF token 和完整的 `Origin`，写入 `/config/draft` 时保留当前 `version`、`base_revision`。

工具向 `--url` 指定地址连接，按 `--host-pattern` 轮换 Host，因此本地 HTTP 测试不依赖这些域名的 DNS。HTTPS 测试需使用拥有有效证书的测试域名，配置 `--server-name`；`--insecure` 仅供显式信任本地测试证书。

## 普通请求

```sh
./bin/wafbench --url http://127.0.0.1:8080 \
  --mode http --sites 50 --rps 1000 --workers 100 --duration 30m
```

请求为约 1 KiB JSON，模拟上游返回 1 KiB。结果包含实际吞吐、状态码、失败、发生器过载、P50/P95/P99 和最多 100000 个蓄水池抽样延迟。发生器过载或非正常错误导致非零退出码。

分别对无 WAF 的模拟上游和 WAF 进行同一场景测试，计算额外延迟。压力发生器与源站最好运行在独立机器；如果共享机器，报告必须说明 CPU 竞争。不要将 macOS 回环短测当作 Linux 生产容量。

## 长连接

```sh
./bin/wafbench --url http://127.0.0.1:8080 \
  --mode sse --sites 50 --connections 1000 --ramp 30s --duration 30m
./bin/wafbench --url http://127.0.0.1:8080 \
  --mode websocket --sites 50 --connections 1000 --ramp 30s --duration 30m
```

SSE 每秒发送事件，WebSocket 每秒发送并回显一条消息。连接按 30 秒逐步建立，避免人为触发握手速率限制；分布在 50 个站点，每站点约 20 条连接。请求结束时的主动取消单独计数。

长连接输出中的 `latency_measure=connection_lifetime` 表示连接存活时长，不是消息往返延迟；只有普通 HTTP 模式的延迟统计表示请求延迟。短时本机冒烟可运行 `python3 scripts/benchmark-smoke.py --out /tmp/waf-benchmark-results`，需要先构建三个 `bin/waf*` 程序，且回环端口 18080、18081、19090 均空闲。该脚本使用临时状态，还会验证命令行加密备份恢复。

验收要求：连接达到目标，持续运行无意外断开；热发布后原连接仍可收发；内存、文件描述符和 goroutine 在稳定负载下不持续增长。检查停止后连接、临时正文文件和请求预算归零。

同时采集 `/metrics` 中的进程 CPU/RSS、Go 堆、goroutine、`waf_connections`、`waf_inflight_requests`、正文预算和事件丢弃计数，保留原始输出及环境信息。再测试上游失效、证书续期失败、磁盘写入失败和优雅退出；功能测试位于 `internal/*/*_test.go`。
