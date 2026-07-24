# JS API Hunter

> 一个 VS Code 扩展，将 JS 接口挖洞的七步手工作坊升级为一键自动化流水线。

[![Version](https://img.shields.io/github/package-json/v/ookini-kawaii/js-api-hunter)](https://github.com/ookini-kawaii/js-api-hunter)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.85.0-blue)](https://code.visualstudio.com/)

输入目标 URL → 自动提取 JS 文件中所有 API 端点 → 越权/IDOR/SQLi/NoSQLi/SSRF/业务逻辑/接口滥用/并发竞态/签名绕过 自动测试 → 横向多子域名 Fuzz → 一键导出专业漏洞报告。

---

## 功能

### 自动化 JS 接口发现
- 输入 URL，优先 HTTP 直连收集，Puppeteer 兜底，自动拦截并收集所有 `.js` 文件
- AST + 正则双引擎解析，提取 API 端点（支持 fetch/axios/router/jQuery/ajax 等）
- 自动识别 `baseURL` / `BASE_URL` / `VUE_APP_API` / `REACT_APP_API` / `process.env.*` / `axios.create` 并拼接完整请求
- 自动发现 `.map` Source Map 并还原源码，扩大代码审计面

### 多维度安全测试（PDF 第 6 章五维度）
- **鉴权维度**：删 Token、改认证头、内网 IP 绕过、普通 Token 调管理接口
- **IDOR**：自动替换路径/Body/Query 中的数字 ID，支持两账号 Token 对比（账号 A 数据账号 B 能否访问）
- **参数注入**：XSS / 原型污染 / 路径遍历 / 超长字符串
- **SQL 注入**：错误检测 + 时间盲注（8 种载荷）
- **NoSQL 注入**：`$ne` / `$gt` / `$exists` / `$regex` / `$where`（6 种载荷）
- **SSRF**：本地回环 / 云元数据 / 文件协议（5 种载荷 × 7 个敏感参数）
- **Mass Assignment**：自动添加 `role=admin` / `isAdmin=true` / `userType=9` 等字段
- **业务逻辑**：`price=0/-1` / `amount=99999999` / 类型混淆 `id=[]`
- **接口滥用**：短信轰炸 / 验证码爆破 / 优惠券重复领取 / 抽奖刷券
- **并发竞态**：同一请求短时间并发，检测重复领取/竞态条件
- **签名绕过**：删除 `sign` / `signature` / `timestamp` / `nonce` 等字段或头，老系统可能直接放行

### 横向 Fuzz（核心杀手锏）
- 子域名前缀爆破 + **crt.sh 证书透明度**补充，按 PDF 出洞率分类：测试环境 > 老系统 > 管理后台 > API
- 同一批接口 × 多个子域名 × 路径变异（去掉 `api/`、去掉版本号、加 `admin` 前缀）
- 每个组合自动测 **带 Token + 裸奔** 两个版本
- 输出横向 Fuzz 矩阵，一眼定位"代码同步了，防护没同步"的脆弱子域

### AI 集成（MCP Server）
内置 MCP Server，可被 Claude Code / Trae CN 等 AI 助手直接调用：
- `scan_url(url)` — 扫描目标
- `fuzz_endpoint(url)` — 测试端点
- `horizontal_fuzz(subdomains)` — 横向 Fuzz
- `generate_report(format)` — 生成报告

### 专业报告
一键导出 HTML / Markdown / JSON / CSV / SRC 漏洞报告模板，含端点矩阵和横向 Fuzz 矩阵。

---

## 安装

### 从 VS Code Marketplace（推荐）
1. 打开 VS Code
2. 按 `Ctrl+Shift+X` 打开扩展面板
3. 搜索 "JS API Hunter"
4. 点击安装

### 从 VSIX 文件
```bash
# 下载 js-api-hunter-x.x.x.vsix
code --install-extension js-api-hunter-x.x.x.vsix
```

### 从源码编译
```bash
git clone https://github.com/ookini-kawaii/js-api-hunter.git
cd js-api-hunter
npm install
npm run compile
```

---

## 使用

### 基本流程

1. **启动扫描**：点击左侧 JS API Hunter 侧边栏的 **开始扫描** 按钮（或 `Ctrl+Shift+P` → `JS API Hunter: 新建扫描`）→ 输入目标 URL → 回车

2. **查看结果**：左侧侧边栏 "JS API Hunter" 面板展示所有发现的 API，按风险 🔴🟡🟢 分组；同时展示敏感信息、按分类分组的子域名

3. **测试端点**：右键端点 → `Fuzz 测试` → 输入测试 Token（可选输入第二个账号 Token 做 IDOR 对比）→ WebView 面板实时展示测试进度和漏洞

4. **横向 Fuzz**：点击侧边栏 **子域名枚举** 按钮先收集子域名，或 `Ctrl+Shift+P` → `JS API Hunter: 横向 Fuzz` → 输入子域名列表 → 自动并发测试

5. **导出报告**：点击侧边栏 **导出结果** 按钮（或 `Ctrl+Shift+P` → `JS API Hunter: 导出结果`）→ 选择格式

### 所有命令

| 命令 | 入口 | 说明 |
|---|---|---|
| `JS API Hunter: 新建扫描` | 侧边栏搜索图标 / Ctrl+Shift+P | 输入 URL 开始扫描 |
| `JS API Hunter: Fuzz 测试端点` | 右键端点 | 对端点执行完整安全测试 |
| `JS API Hunter: 横向 Fuzz` | Ctrl+Shift+P | 批量多子域名测试 |
| `JS API Hunter: 子域名枚举` | 侧边栏地球图标 | 前缀爆破 + crt.sh |
| `JS API Hunter: 分析签名/加密逻辑` | Ctrl+Shift+P | 检测 JS 中的签名函数并生成 Console 脚本 |
| `JS API Hunter: 查看敏感信息` | 侧边栏钥匙图标 | 展示提取的密钥/域名 |
| `JS API Hunter: 重放验证端点` | Ctrl+Shift+P | 确认端点可达 |
| `JS API Hunter: MCP 集成配置` | Ctrl+Shift+P | 配置 Claude Code 调用扩展 |
| `JS API Hunter: 导出结果` | 侧边栏保存图标 | 导出 HTML/Markdown/JSON/CSV/SRC 报告 |
| `查看端点详情` | 右键端点 | 查看完整请求信息 |
| `复制完整请求` | 右键端点 | 复制 curl-ready 请求 |

---

## MCP 集成（Claude Code 调用）

在 Claude Code / Trae CN 的 MCP 配置中添加：

```json
{
  "mcpServers": {
    "js-api-hunter": {
      "command": "node",
      "args": ["/path/to/js-api-hunter/dist/mcp/server.js"],
      "description": "JS API Hunter - JS 接口自动发现与测试"
    }
  }
}
```

配置后可以在 Claude Code 中：
```
> 扫描 https://target.com 并找出所有高风险 API 端点
> 对 /api/admin/users 进行越权测试
> 横向测试 test.target.com 和 dev.target.com
> 导出 SRC 漏洞报告
```

---

## 配置项

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `jsApiHunter.concurrentRequests` | 10 | Fuzz 并发请求数 |
| `jsApiHunter.timeout` | 30000 | 请求超时（毫秒） |
| `jsApiHunter.userAgent` | Chrome UA | 自定义 User-Agent |
| `jsApiHunter.userToken` | "" | 默认测试 Token |
| `jsApiHunter.verifyEndpoints` | true | 扫描后自动重放验证端点 |
| `jsApiHunter.pathVariants` | true | 横向 Fuzz 启用路径变异 |
| `jsApiHunter.subdomainPrefixes` | 35 个前缀 | 子域名爆破前缀列表 |
| `jsApiHunter.testAuthBypass` | true | 测试鉴权绕过 |
| `jsApiHunter.testIdor` | true | 测试 URL 路径 IDOR |
| `jsApiHunter.testIdorBody` | true | 测试 Body/Query IDOR |
| `jsApiHunter.testParamInject` | true | 测试参数注入 |
| `jsApiHunter.testSqlInject` | true | 测试 SQL 注入 |
| `jsApiHunter.testNoSqlInject` | true | 测试 NoSQL 注入 |
| `jsApiHunter.testSsrf` | true | 测试 SSRF |
| `jsApiHunter.testMassAssignment` | true | 测试 Mass Assignment |
| `jsApiHunter.testBusinessLogic` | true | 测试业务逻辑 |
| `jsApiHunter.testInterfaceAbuse` | true | 测试接口滥用 |
| `jsApiHunter.testRaceCondition` | true | 测试并发竞态 |
| `jsApiHunter.testSignBypass` | true | 测试签名绕过 |

---

## 项目结构

```
src/
├── extension.ts           # VS Code 扩展入口
├── commands.ts            # 命令注册
├── types.ts               # 完整类型定义
├── collector/
│   ├── collector.ts       # JS 收集器（HTTP + Puppeteer）
│   └── sourcemap.ts       # Source Map 发现与还原
├── parser/parser.ts       # AST + 正则端点解析器
├── assembler/assembler.ts # baseURL 识别 + 请求拼接 + 重放验证
├── fuzzer/
│   ├── fuzzer.ts          # 测试引擎（垂直 + 横向）
│   └── payloads.ts        # 60+ 种测试载荷
├── signer/signer.ts       # 签名/加密逻辑分析
├── secrets/secrets.ts     # 敏感信息提取（SecretFinder）
├── recon/subdomains.ts    # 子域名枚举（前缀爆破 + crt.sh）
├── webview/fuzzerPanel.ts # WebView 实时测试面板
├── tree/endpointTree.ts   # TreeView 端点浏览器
└── mcp/server.ts          # MCP Server（AI 集成）
```

---

## 适用场景

- SRC 漏洞挖掘
- 渗透测试前期侦察
- Bug Bounty
- Web 应用安全评估
- 安全教学演示

---

## 安全声明

本工具仅供授权安全测试使用。使用本工具对未授权目标进行扫描可能违反法律法规。使用者需自行承担风险。

---

## License

MIT © ookini-kawaii
