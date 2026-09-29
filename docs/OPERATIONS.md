# 部署与运维

## 安装

安装脚本支持 Ubuntu 22.04+、Debian 12+，Linux amd64/arm64，systemd 247+。默认单机本地存储，不共享 SQLite 文件，不同时运行多个 WAF 进程。

### 自动安装

准备管理域名、ACME 邮箱和 Cloudflare Token。Token 需要相应 Zone 的 `DNS:Edit` 与 `Zone:Read` 权限。域名 A/AAAA 记录应指向服务器；只配置服务器实际可用的地址。开放入站 80/443，保持 9090 仅本机可访问，并允许出站 HTTPS 和 DNS。

```sh
curl -fsSLo install-waf.sh https://github.com/NeptuneIsTheBest/WAF/releases/latest/download/install.sh &&
sudo bash install-waf.sh
```

脚本支持 `--version v0.1.0`、`--domain waf-admin.example.com`、`--email operator@example.com`。默认获取最新正式版本，并从同一个版本下载对应架构的安装包和 SHA-256 清单。脚本自动补齐系统工具，不在服务器上编译程序，不改动防火墙规则。

密码和 Token 从终端隐藏输入；TOTP 密钥及恢复码仅显示在当前终端。使用 SSH 交互终端运行，不要录制安装会话。管理账号默认为 `admin`。

脚本安装到 `/usr/local/bin/waf`，启动配置和主密钥位于 `/etc/waf`，数据位于 `/var/lib/waf`。服务以专用 `waf` 账号运行，并设置开机自启。安装成功要求本机 `/readyz` 与管理域名 HTTPS 检查通过；公网是否可达还取决于 DNS、安全组及防火墙配置。

证书超过 5 分钟仍未就绪时，脚本报告失败并保留服务和数据。修正 Cloudflare 权限或出站网络后，证书管理器会继续尝试签发，可查看：

```sh
sudo systemctl status waf
sudo journalctl -u waf -n 80
sudo waf doctor --config /etc/waf/waf.json
```

安装器不会覆盖已有二进制、配置、数据、服务或账号；重复执行也不会重置密码。初始化阶段中断时，先检查错误和现有文件，按下面的手动步骤完成剩余操作；不要删除已有的主密钥或数据库。升级参见文末。

### 手动安装

1. 从 [GitHub Releases](https://github.com/NeptuneIsTheBest/WAF/releases) 下载对应架构的发布包和 `SHA256SUMS`，校验下载文件后解压。
2. 创建专用账号并安装文件：

```sh
sudo useradd --system --user-group --no-create-home --home-dir /var/lib/waf --shell /usr/sbin/nologin waf
sudo install -m 0755 waf /usr/local/bin/waf
sudo install -d -m 0750 -o root -g waf /etc/waf
sudo install -d -m 0700 -o waf -g waf /var/lib/waf
sudo install -d /usr/local/share/waf
sudo cp -R docs /usr/local/share/waf/
sudo install -m 0644 deploy/waf.service /etc/systemd/system/waf.service
```

3. 初始化。需要控制 Cloudflare 中的域名；DNS 编辑 Token 应仅授权需要管理的 Zone，按 provider 要求另外提供 Zone 查询权限。后台域名和业务域名的流量记录需要指向 WAF；DNS-01 签发本身不要求开放 80 端口。

```sh
sudo /usr/local/bin/waf init --config /etc/waf/waf.json \
  --domain waf-admin.example.com --email operator@example.com
sudo chown root:waf /etc/waf/waf.json
sudo chmod 0640 /etc/waf/waf.json
sudo chmod 0600 /etc/waf/master.key
sudo chown -R waf:waf /var/lib/waf
sudo systemctl daemon-reload
sudo systemctl enable --now waf
sudo journalctl -u waf -f
```

初始化接受 ACME CA 的订户条款。首次使用可在单独测试数据目录中传入 `--staging` 使用 Let's Encrypt 测试 CA；测试证书不受浏览器信任。生产部署使用生产 CA 和独立证书数据，避免混用测试与生产缓存。

主密钥保留 root 所有，systemd 通过 `LoadCredential=master.key:...` 复制到受保护的运行时目录。程序在 `CREDENTIALS_DIRECTORY` 存在时使用该目录里的 `master.key`。`waf.json` 只包含非秘密启动设置。

配置 `admin_cidrs` 可限制控制台来源。只在 `trusted_proxies` 中加入确实由你控制的代理网络；系统从右往左解析 X-Forwarded-For，遇到不可信地址立即停止。外部提交的 CF-Connecting-IP 和 True-Client-IP 不作为身份来源，回源时删除。

业务源站应仅允许 WAF 访问，避免绕过 WAF 直接访问源站。默认只接受配置过的域名，不按客户端 Host 动态申请证书。后台域名不能被普通站点或通配符站点覆盖。

## 首次接入与发布

1. 添加站点、域名与上游，确认健康检查路径返回 2xx/3xx；不需要主动检查时留空。
2. 在观察模式下回放正常业务，检查 JSON、表单、上传、登录等路径的命中情况。
3. 对具体检测规则建立尽量窄的参数／路径例外。CRS 初始化、分数汇总和报告规则不能作为例外禁用。
4. 在“安全规则 → 托管规则 → 配置托管规则”切换为拦截模式，校验配置后发布。
5. 新规则先使用 `log` 动作验证。浏览器挑战仅用于适合交互的页面；不要自动重放 API、上传或带副作用的请求。

保存草稿不会影响流量。发布时编译整个配置，先持久化一个新版本，再原子切换内存快照。并发编辑使用草稿版本检查，过期修改返回 409。失败继续使用旧版本；已有长连接不因规则热更新而重建。新规则只影响新请求与新握手。

启动配置中的监听、资源限制、管理域名和信任代理变化需要重启。站点和规则通过后台热更新。源站 URL 仅支持 HTTP/HTTPS origin，不包含路径、用户信息、查询或片段。HTTPS 回源校验证书；没有关闭证书校验的生产选项。

## 安全规则与质询

“安全规则”页面统一选择站点，下设自定义规则、速率限制规则和托管规则三个分区。自定义规则支持 Block、Skip、Log、Managed Challenge、Non-Interactive Challenge 和 Interactive Challenge。Skip 可以选择剩余自定义规则、全部速率限制规则、托管规则或指定规则，始终保留协议与资源限制。

质询高级设置按规则独立保存：`work_factor` 默认 5000、允许 1000–20000；`clearance_seconds` 默认 1800 秒、允许 60–86400 秒。计算强度越高，浏览器耗时越长。每站点最多 16 条质询规则。生产环境验证需要 HTTPS；浏览器需要 JavaScript、Web Crypto 和 Web Worker。

Non-Interactive 自动计算，Interactive 点击复选框后计算，Managed 根据本地请求频率与失败记录选择方式。Managed 在令牌桶耗尽（每秒补充 2 个、容量 120）或 5 分钟内失败 3 次时选用交互模式。ALTCHA 是本地开源工作量验证，点击本身不构成不可伪造的人类身份证明；需要限制请求频率时，应同时配置速率限制规则。

质询资源随 WAF 打包，不需要 ALTCHA 账号、密钥或额外服务。旧独立 Bot 模型、`challenge` 动作和路径级 `allow_challenge` 开关已移除，本版本不转换旧配置、历史版本或旧备份；使用新模型重新建立规则。可疑 User-Agent 用 CEL 的 `request.user_agent.matches(...)` 配置，频率阈值放入速率限制规则。

API、上传、SSE 和 WebSocket 命中质询时返回结构化 403，包含 `challenge_url`、`action` 和 `challenge_mode`。在相同客户端环境完成验证后，由调用方重试原请求。验证服务不会自动重发这些请求。安全事件保留具体 Action、规则 ID 和实际验证方式；质询静态资源不计入安全事件。

## 证书与凭据

证书私钥与 ACME 账户存放于 `/var/lib/waf/certificates`，目录权限 0700。Cloudflare Token 和 TOTP 密钥使用 AES-GCM 加密保存在数据库，绑定各自的记录身份。

在后台更新凭据后，证书自动化会重新使用新凭据。关注有效期、最近错误和日志；有效旧证书在续期失败时继续工作，到期后需要修复 DNS 权限、传播、出站 DNS/HTTPS 或 CA 限制。管理后台证书尚未就绪时，HTTPS 握手不会降级到明文后台，可使用本机 `doctor` 与 journald 排查。

```sh
sudo waf doctor --config /etc/waf/waf.json
curl --fail http://127.0.0.1:9090/livez
curl --fail http://127.0.0.1:9090/readyz
```

生产模式始终要求密码与 TOTP，TOTP 同一时间步仅接受一次。恢复码使用一次后失效。角色变化会撤销该用户所有会话。遗失认证资料时通过本机恢复：

```sh
sudo systemctl stop waf
sudo waf reset-admin --config /etc/waf/waf.json --username admin
sudo systemctl start waf
```

## 备份与恢复

后台可创建和下载 age 密码加密备份，最多保留 10 个文件。备份采用 SQLite 一致性快照，复制证书时验证证书和私钥匹配；遇到签发／续期竞争会失败并要求重试。归档不包含主密钥。备份密码、原始主密钥和备份文件必须分别保管。

本机命令使用进程锁，需停止服务：

```sh
sudo systemctl stop waf
sudo waf backup --config /etc/waf/waf.json --out /secure-backups/waf.age
sudo systemctl start waf
```

恢复时先配置正确的启动文件和原始 `master.key`，再执行：

```sh
sudo systemctl stop waf
sudo waf restore --config /etc/waf/waf.json --in /secure-backups/waf.age
sudo waf check --config /etc/waf/waf.json
sudo chown -R waf:waf /var/lib/waf
sudo systemctl start waf
```

恢复检查 age 认证、路径安全、大小上限、主密钥指纹、SQLite 完整性与规则编译；成功后替换数据目录。旧目录保留为 `.pre-restore-时间`，请在验收后归档清理。恢复操作不通过公网 API 提供。

## 日志、指标与资源

- 业务请求不访问配置数据库；事件经 4096 条有界队列异步批量写入独立 SQLite 数据库。队列满或写入失败时丢弃事件并增加指标，不阻塞代理。
- 默认事件最多保留 7 天、200000 条，两者取先达到的限制；数据库复用空闲页，文件不会每次清理后立即缩小。在持续 1000 RPS 且全部请求记录时，200000 条仅覆盖约三分钟，应按实际留存需求调整容量或导出到外部日志系统。
- 管理操作审计存入配置库，保留 90 天且最多 200000 条。配置发布、角色修改、凭据更新与审计在同一事务中提交。
- 事件不保存请求正文、查询参数值、Authorization 或 Cookie。日志页面始终以文本呈现输入。
- `body_budget_bytes` 默认 256 MiB，按完整检查请求的三倍正文容量预留，覆盖回放缓冲、Coraza 缓冲及 multipart 临时文件；超过 128 KiB 的正文使用临时文件。请求结束清理文件，启动时清理崩溃留下的正文文件。解析器对象仍有额外内存开销，需要结合 systemd 内存上限和实测调整。
- 默认最多 8192 个 TCP 连接、1024 个进行中的请求、每条路径 256 个请求、每 IP/站点 32 个 WebSocket 连接。SSE 占用请求与路径并发额度。
- 限流缓存默认最多 100000 个键，活跃键不会为新键让出容量；缓存满时拒绝新键。速率、临时封禁和连接计数是本机内存状态，重启会重置。
- 数据库不可写时，配置与认证管理操作失败；已有代理快照继续服务。冷启动没有可加载的有效配置时拒绝启动。

指标仅绑定回环地址。参考 [Prometheus 配置](../deploy/prometheus.yml) 与 [告警规则](../deploy/alerts.yml)，将指标接入已有监控系统。仓库不会自动向第三方发送告警消息。

## 升级与回滚

1. 下载、校验新二进制，阅读依赖与 CRS 变更。
2. 创建备份，在测试环境恢复后运行新版本 `check` 和业务回归。
3. 停止服务，替换二进制，启动并检查健康、证书和正常流量。
4. 保留旧二进制和完整旧数据备份；涉及未来数据库迁移时，软件回滚必须同时恢复兼容的数据。

首版数据库 schema 为 1，不支持静默读取未知 schema。配置版本回滚只恢复配置，规则集版本回退需要回退软件。SIGTERM 最长排空 30 秒，随后关闭仍存活的 HTTP、SSE 和 WebSocket 连接；客户端应具备正常的重连能力。
