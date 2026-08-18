# Changelog

## 0.3.4 (2026-08-18)

### 安全
- 将 `puppeteer-core` 升级至已修复版本，清除依赖审计中的高风险告警。

## 0.3.3 (2026-08-18)

### 修复
- 修复被动代理处理 HTTPS CONNECT 时丢弃首段缓冲数据的问题，提升浏览器代理连接兼容性。
- 恢复 HTTPS 上游证书校验，避免安全工具默认接受无效证书。
- MCP 初始化响应同步扩展版本号，并将代理回归测试接入 `npm test` 与 CI。

## 0.3.2 (2026-07-27)

### 新增
- **端点智能过滤**：扫描后自动去重、排除静态资源（.js/.css/.png 等）和非 API 端点（/dist/、/assets/、/node_modules/ 等），从 3000+ 噪声端点大幅缩减至真正有价值的 API 接口。可在设置中关闭或自定义保留/排除关键词。
- **Cookie 认证支持**：新增 `jsApiHunter.userCookie` 配置项和 Cookie 输入弹窗，支持从浏览器 DevTools 复制 Cookie 字符串进行认证测试。Fuzz 时自动附加 Cookie 头，兼容 Cookie-based 鉴权的 Web 应用。
- **被动代理模式**：启动本地 HTTP/HTTPS 代理服务器，捕获浏览器流量并自动收集 JS 文件。在浏览器设置代理为 `localhost:8080` 后浏览目标网站即可自动收集，无需手动输入 URL。

### 改进
- 欢迎面板新增 "启动被动代理" 快捷入口
- 状态栏支持代理运行状态实时显示（JS 收集计数）
- TreeView 显示过滤统计和摘要（已过滤 X 个非 API 端点）
- `getUserAuth` 支持 Token/Cookie/跳过 三种认证方式弹窗选择

### 配置
- 新增 `jsApiHunter.filterEndpoints`：是否启用端点智能过滤（默认开启）
- 新增 `jsApiHunter.filterKeepKeywords`：额外保留的路径关键词
- 新增 `jsApiHunter.filterExcludeKeywords`：额外排除的路径关键词
- 新增 `jsApiHunter.userCookie`：默认测试 Cookie 字符串
- 新增 `jsApiHunter.proxyPort`：被动代理默认端口（默认 8080）

## 0.3.1 (2026-07-24)

### 修复
- **修复重放验证端点卡住问题**：`verifyEndpoints` 改为并发探测（默认 5 并发），单个端点超时从 10 秒降至 5 秒，并添加 `AbortController` 双重超时保护
- **修复取消不生效问题**：重放验证期间点击取消后，使用 `vscode.CancellationToken + AbortController` 立即中断所有进行中的 `fetch` 请求

### 改进
- **图标更换**：左侧活动栏图标从 `$(bug)` 改为 `$(search)`，状态栏同步更新
- **版本徽章**：README 版本徽章改为 GitHub 动态徽章，自动跟随 `package.json` 版本

### 配置
- 新增 `jsApiHunter.verifyTimeout`：单个端点验证超时（默认 5000ms）
- 新增 `jsApiHunter.verifyConcurrency`：验证并发数（默认 5）

## 0.3.0 (2026-07-23)

根据《JS 接口挖洞实战教程 —— 从入门到横向 Fuzz》PDF 进行的能力补齐：

### 新增测试维度
- **NoSQL 注入**：新增 `$ne` / `$gt` / `$exists` / `$regex` / `$where` 等 MongoDB 风格载荷
- **接口滥用**：新增短信轰炸、验证码爆破、优惠券重复领取、抽奖刷券等载荷
- **并发竞态**：对同一端点短时间并发发送请求，检测重复领取/竞态漏洞
- **签名绕过**：自动删除常见签名字段/头（`sign` / `signature` / `timestamp` / `nonce`），适配老系统签名失效场景

### IDOR 增强
- 支持输入**第二个账号 Token**，fuzz 时自动对比账号 A 与账号 B 的数据访问边界，实现 PDF 强调的两账号越权测试核心

### 子域名枚举增强
- 新增 **crt.sh 证书透明度**来源补充子域名
- 子域名按 PDF 出洞率分类：测试环境 / 老系统 / 管理后台 / API / 内部域名 / 其他
- HTTP 存活探测状态码对齐 PDF 推荐：只保留 200 / 302 / 401 / 403

### baseURL 识别增强
- 新增 `BASE_URL`、各类 `process.env.*` 环境变量匹配模式

### 报告增强
- Markdown 报告新增**横向 Fuzz 矩阵**，直观展示"接口 × 域名"的命中结果

### 配置增强
- package.json 新增 12 个测试开关配置项，可在 VS Code 设置中单独开启/关闭每个测试维度

### 其他
- 版本号升级至 0.3.0
- README 全面更新，反映新增能力与配置项

## 0.2.0

- 新增敏感信息提取（SecretFinder）
- 新增 Source Map 自动发现与源码还原
- 新增子域名枚举
- 新增 Mass Assignment / 业务逻辑测试 / 路径变异
- 新增 CSV / SRC 报告格式
- 优化 TreeView 交互与欢迎面板
- MCP 集成

## 0.1.0

- 初始版本：JS 收集、端点解析、baseURL 拼装、越权/IDOR/SQLi/SSRF 测试、横向 Fuzz
