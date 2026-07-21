# JS API Hunter — 设计文档

> 一个 VS Code 扩展，将 JS 接口挖洞的七步手工作坊升级为一键自动化流水线。

---

## 一、项目概述

### 1.1 一句话描述

输入目标 URL，自动提取 JS 文件中的所有 API 端点，拼装完整请求，批量进行越权/Fuzz 测试，一键导出漏洞报告。

### 1.2 目标用户

白帽子、渗透测试工程师、SRC 漏洞猎人。

### 1.3 竞品定位

| 工具 | 形态 | 与本项目的区别 |
|---|---|---|
| LinkFinder | Python CLI | 仅提取端点，无测试，无 GUI |
| Anastasis | Node.js CLI | 仅提取端点，无 VS Code 集成 |
| BurpJSLinkFinder | Burp 插件 | 绑定 Burp Suite，不开 Burp 用不了 |
| VS Code 安全扩展 | VS Code 扩展 | 全是防御向（SAST/依赖扫描），无攻击向工具 |

**VS Code Marketplace 上目前没有同类攻击向 JS 接口发现工具，市场空白。**

---

## 二、用户体验流程

### 完整路径（用户最少操作步骤）

```
输入 URL → 等结果 → 看漏洞 → 导出报告
```

### 详细交互

1. **启动扫描**：`Ctrl+Shift+P` → "JS API Hunter: 新建扫描" → 输入 URL → 回车
2. **自动收集**：内置 Puppeteer 打开网站，自动拦截所有 .js 文件，收集完毕后关闭浏览器。无需配代理、无需手动浏览。
3. **自动分析**：AST 解析提取端点，自动识别 baseURL 并拼接完整请求
4. **查看结果**：左侧 TreeView 展示所有发现的 API，🔴高/🟡中/🟢低 按风险分级
5. **一键测试**：右键接口 → "发送到 Fuzzer" → 自动越权/IDOR/注入/横向Fuzz
6. **导出报告**：一键生成 HTML/Markdown 格式漏洞报告

### 原始流程 vs 自动化后

| 原始手动流程 | 扩展自动化 |
|---|---|
| Burp 配代理、手动浏览 | Puppeteer 自动打开网站 |
| 导出 JS、跑 LinkFinder | 内置引擎自动提取 |
| 人工搜 baseURL 拼接 | AST 自动识别 + 拼接 |
| 浏览器 Console 调签名 | 自动识别签名逻辑，提示调用模板 |
| Burp Repeater 一发发测 | Fuzzer 一键并发测试 |
| 手动换域名重复测 | 横向 Fuzz 自动扫所有子域 |
| 手动整理写报告 | 一键导出 |

---

## 三、核心模块

### 3.1 Collector（JS 收集器）
- Puppeteer 自动浏览目标网站
- 拦截网络请求，收集全部 .js 文件
- 可选：Wayback Machine 等被动来源补充

### 3.2 Parser（端点解析器）
- AST 解析 JS 代码，提取 API 端点
- 正则辅助识别常见模式
- 提取参数、method、路径

### 3.3 Assembler（请求拼接器）
- 自动识别 baseURL（搜 `baseURL`、`VUE_APP_API`、`axios.create` 等）
- 拼接完整 HTTP 请求（URL + method + headers + body）

### 3.4 SignAnalyzer（签名分析器）
- 识别 JS 中的签名/加密逻辑（搜 `sign`、`encrypt`、`md5` 等）
- 生成 Console 调用模板（不自动破解，因为每个站逻辑不同）

### 3.5 Fuzzer（测试引擎）
- **垂直测试**：越权（删 Token）、IDOR（改 ID）、参数注入、业务逻辑
- **横向 Fuzz**：同一接口清单打到多个子域名，找出"代码同步但防护没同步"的环境

### 3.6 Reporter（报告生成器）
- 汇总发现的漏洞，按风险分级
- 支持 HTML / Markdown / JSON 输出

---

## 四、分阶段计划

### Phase 1：核心 MVP
**目标**：输入 URL → 输出接口列表  
**内容**：Collector + Parser + Assembler + TreeView  
**产出**：可用的 VS Code 扩展，能展示完整接口列表  
**时间**：2-3 周

### Phase 2：测试引擎
**目标**：能挖到真实漏洞  
**内容**：Fuzzer（垂直 + 横向）+ WebView 面板  
**产出**：越权/IDOR/横向Fuzz 能力  
**时间**：2-3 周

### Phase 3：体验打磨
**目标**：专业度和易用性提升  
**内容**：MCP Server 集成、签名分析、报告导出、配置面板  
**产出**：完整产品体验  
**时间**：1-2 周

### Phase 4：发布上线
**目标**：推到市场  
**内容**：打包 .vsix、上架 Marketplace、GitHub 开源、写文档  
**时间**：1 周

---

## 五、技术选型

| 层 | 技术 |
|---|---|
| 扩展框架 | VS Code Extension API（TypeScript） |
| UI - 侧边栏 | TreeView API |
| UI - 工作台 | WebView（HTML/CSS） |
| 浏览器自动化 | Puppeteer（拦截网络请求收集 JS） |
| JS 解析 | acorn（AST）+ 正则辅助 |
| HTTP 引擎 | undici（高并发，Fuzzer 用） |
| 报告生成 | 纯字符串模板（HTML/Markdown） |
| MCP 集成 | 内置 MCP Server（给 Claude Code 调用） |

---

## 六、MCP 集成设计（Phase 3）

扩展内置一个 MCP Server，暴露以下工具给 Claude Code / 其他 AI 调用：

| 工具名 | 功能 |
|---|---|
| `scan_url(url)` | 扫描目标，收集 JS 并提取端点 |
| `get_endpoints()` | 获取当前发现的接口列表 |
| `get_endpoint_detail(id)` | 查看某个接口的完整信息（headers/body/参数） |
| `fuzz_endpoint(id)` | 对指定接口执行完整测试 |
| `horizontal_fuzz(endpoint_ids)` | 对指定接口集执行横向多域名 Fuzz |
| `generate_report(format)` | 生成漏洞报告 |
| `get_scan_status()` | 查看当前扫描进度 |

---

## 七、不做的事情（明确边界）

- **不自动破解签名**：每个站的加密逻辑不同，自动破解不现实。只做"识别 + 提示模板"
- **不做漏洞利用**：只做漏洞发现和验证（PoC 级别），不做深入利用
- **不做被动扫描**：Phase 1 不做 Burp 流量监听等被动模式，只做主动扫描
- **不强制 AI 依赖**：MCP 集成为可选项，不装 Claude Code 也能正常使用
