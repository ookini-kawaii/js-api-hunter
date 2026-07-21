# JS API Hunter

> 一个 VS Code 扩展，将 JS 接口挖洞的七步手工作坊升级为一键自动化流水线。

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/ookini-kawaii/js-api-hunter)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.85.0-blue)](https://code.visualstudio.com/)

输入目标 URL → 自动提取 JS 文件中所有 API 端点 → 越权/IDOR/SQLi/SSRF 自动测试 → 横向多子域名 Fuzz → 一键导出专业漏洞报告。

---

## 功能

### 自动化 JS 接口发现
- 输入 URL，内置浏览器自动拦截并收集所有 `.js` 文件
- AST + 正则双引擎解析，提取 API 端点（支持 fetch/axios/router/jQuery/ajax 等）
- 自动识别 `baseURL` / `VUE_APP_API` / `axios.create` 并拼接完整请求

### 多维度安全测试
- **越权测试**：删 Token、改认证头、内网 IP 绕过（9 种 Header 组合）
- **IDOR**：自动替换路径中的数字 ID
- **参数注入**：XSS / NoSQL / Mass Assignment / 路径遍历（9 种载荷）
- **SQL 注入**：错误检测 + 时间盲注（8 种载荷）
- **SSRF**：本地回环 / 云元数据 / 文件协议（5 种载荷 × 7 个敏感参数）

### 横向 Fuzz（核心杀手）
同一个接口清单打到多个子域名（test/dev/staging/admin...），发现"代码同步了，防护没同步"的裸奔环境。

### AI 集成（MCP Server）
内置 MCP Server，可被 Claude Code 等 AI 助手直接调用：
- `scan_url(url)` — 扫描目标
- `fuzz_endpoint(url)` — 测试端点
- `horizontal_fuzz(subdomains)` — 横向 Fuzz
- `generate_report(format)` — 生成报告

### 专业报告
一键导出 HTML / Markdown / JSON 格式的漏洞报告，含端点和 Fuzz 结果。

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

1. **启动扫描**：`Ctrl+Shift+P` → `JS API Hunter: 新建扫描` → 输入目标 URL → 回车

2. **查看结果**：左侧侧边栏 "JS API Hunter" 面板展示所有发现的 API，按风险 🔴🟡🟢 分组

3. **测试端点**：右键端点 → `Fuzz 测试` → WebView 面板实时展示测试进度和漏洞

4. **横向 Fuzz**：`Ctrl+Shift+P` → `JS API Hunter: 横向 Fuzz` → 输入子域名列表 → 自动并发测试

5. **导出报告**：`Ctrl+Shift+P` → `JS API Hunter: 导出结果` → 选择格式

### 所有命令

| 命令 | 快捷键 | 说明 |
|---|---|---|
| `JS API Hunter: 新建扫描` | 侧边栏搜索图标 | 输入 URL 开始扫描 |
| `JS API Hunter: Fuzz 测试端点` | 右键端点 | 对端点执行完整安全测试 |
| `JS API Hunter: 横向 Fuzz` | `Ctrl+Shift+P` | 批量多子域名测试 |
| `JS API Hunter: 分析签名/加密逻辑` | `Ctrl+Shift+P` | 检测 JS 中的签名函数并生成 Console 脚本 |
| `JS API Hunter: MCP 集成配置` | `Ctrl+Shift+P` | 配置 Claude Code 调用扩展 |
| `JS API Hunter: 导出结果` | `Ctrl+Shift+P` | 导出 HTML/Markdown/JSON 报告 |
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
      "args": ["/path/to/js-api-hunter/out/mcp/server.js"],
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
```

---

## 配置项

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `jsApiHunter.concurrentRequests` | 10 | Fuzz 并发请求数 |
| `jsApiHunter.timeout` | 30000 | 请求超时（毫秒） |
| `jsApiHunter.passiveSources` | true | 是否启用被动来源收集 |
| `jsApiHunter.userAgent` | Chrome UA | 自定义 User-Agent |

---

## 项目结构

```
src/
├── extension.ts           # VS Code 扩展入口
├── commands.ts            # 10 个命令注册
├── types.ts               # 完整类型定义
├── collector/collector.ts # Puppeteer JS 收集器
├── parser/parser.ts       # AST + 正则端点解析器
├── assembler/assembler.ts # baseURL 识别 + 请求拼接
├── fuzzer/
│   ├── fuzzer.ts          # 测试引擎（垂直 + 横向）
│   └── payloads.ts        # 42 种测试载荷
├── signer/signer.ts       # 签名/加密逻辑分析
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
