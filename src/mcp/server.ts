/**
 * JS API Hunter - MCP Server
 * 暴露扫描/Fuzz 工具给 Claude Code 等 MCP 客户端调用
 *
 * 使用方式：
 *   node out/mcp/server.js
 *   Claude Code 配置中添加到 mcpServers:
 *   {
 *     "mcpServers": {
 *       "js-api-hunter": {
 *         "command": "node",
 *         "args": ["d:\\trae doc\\js接口发现\\out\\mcp\\server.js"]
 *       }
 *     }
 *   }
 */

import * as readline from 'readline';
import { collectJsFiles } from '../collector/collector';
import { parseEndpoints } from '../parser/parser';
import { assembleRequests } from '../assembler/assembler';
import { runFuzz, runHorizontalFuzz } from '../fuzzer/fuzzer';
import { EndpointInfo, FuzzResult, ScanContext, FuzzConfig } from '../types';

// 模拟 VS Code 配置
function getConfig(): { concurrentRequests: number; timeout: number; userAgent: string; userToken?: string } {
  return {
    concurrentRequests: 10,
    timeout: 30000,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    userToken: process.env.JS_API_HUNTER_TOKEN
  };
}

// 全局状态
let endpoints: EndpointInfo[] = [];
let fuzzResults: FuzzResult[] = [];
let targetUrl = '';

// MCP 工具定义
const TOOLS = [
  {
    name: 'scan_url',
    description: '扫描目标网站，自动收集所有 JS 文件并提取 API 端点',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: '目标网站 URL' }
      },
      required: ['url']
    }
  },
  {
    name: 'get_endpoints',
    description: '获取最后扫描发现的所有 API 端点及其风险等级',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'get_high_risk_endpoints',
    description: '获取高风险等级（HIGH）的 API 端点',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'fuzz_endpoint',
    description: '对指定端点执行完整的越权/注入测试',
    inputSchema: {
      type: 'object',
      properties: {
        endpoint_index: { type: 'number', description: '端点索引（从 get_endpoints 结果的顺序）' },
        url: { type: 'string', description: '端点完整 URL（替代 endpoint_index）' },
        method: { type: 'string', description: 'HTTP method（配合 url 使用）' }
      },
      required: []
    }
  },
  {
    name: 'horizontal_fuzz',
    description: '对发现的端点执行横向多子域名 Fuzz 测试',
    inputSchema: {
      type: 'object',
      properties: {
        subdomains: {
          type: 'array',
          items: { type: 'string' },
          description: '子域名列表，如 ["test.target.com", "dev.target.com"]'
        }
      },
      required: ['subdomains']
    }
  },
  {
    name: 'generate_report',
    description: '生成漏洞报告',
    inputSchema: {
      type: 'object',
      properties: {
        format: { type: 'string', description: '报告格式: json | markdown' }
      },
      required: ['format']
    }
  },
  {
    name: 'get_scan_status',
    description: '获取当前扫描状态和统计信息',
    inputSchema: { type: 'object', properties: {} }
  }
];

function log(message: string): void {
  process.stderr.write(`[JS API Hunter MCP] ${message}\n`);
}

function sendResponse(response: any): void {
  // 使用 Buffer.write 保证原子写入，避免多进程并发时输出交错
  const json = JSON.stringify(response);
  const buffer = Buffer.from(json + '\n', 'utf-8');
  process.stdout.write(buffer);
}

function startStdioServer(): void {
  log('MCP stdio server starting...');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on('line', async (line: string) => {
    try {
      const request = JSON.parse(line);
      const response = await handleMcpRequest(request);
      sendResponse(response);
    } catch (err: any) {
      sendResponse({
        jsonrpc: '2.0',
        error: { code: -32700, message: `Parse error: ${err.message}` },
        id: null
      });
    }
  });

  rl.on('close', () => {
    log('stdin closed, shutting down');
    process.exit(0);
  });

  // 保持进程存活，等待 stdin 输入
  process.stdin.resume();
}

async function handleMcpRequest(request: any): Promise<any> {
  const { method, params, id } = request;

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'js-api-hunter', version: '0.1.0' },
          capabilities: { tools: {} }
        },
        id
      };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        result: { tools: TOOLS },
        id
      };

    case 'tools/call':
      return {
        jsonrpc: '2.0',
        result: await callTool(params.name, params.arguments || {}),
        id
      };

    case 'notifications/initialized':
      return { jsonrpc: '2.0', result: {}, id };

    default:
      return {
        jsonrpc: '2.0',
        error: { code: -32601, message: `Unknown method: ${method}` },
        id
      };
  }
}

async function callTool(name: string, args: any): Promise<any> {
  switch (name) {
    case 'scan_url': {
      const url = args.url;
      if (!url) { return { content: [{ type: 'text', text: 'ERROR: url is required' }] }; }

      targetUrl = url;

      const jsFiles = await collectJsFiles(url, (count) => {
        log(`  Collecting JS files: ${count}`);
      });

      log(`Collected ${jsFiles.length} JS files`);

      const rawEndpoints = parseEndpoints(jsFiles);
      assembleRequests(rawEndpoints, jsFiles);
      endpoints = rawEndpoints;

      const highCount = endpoints.filter(e => e.riskLevel === 'high').length;
      const mediumCount = endpoints.filter(e => e.riskLevel === 'medium').length;

      return {
        content: [{
          type: 'text',
          text: `扫描完成: ${targetUrl}\n` +
            `- JS 文件: ${jsFiles.length} 个\n` +
            `- API 端点: ${endpoints.length} 个\n` +
            `- 高风险: ${highCount} 个\n` +
            `- 中风险: ${mediumCount} 个\n\n` +
            `高风险端点:\n` +
            endpoints.filter(e => e.riskLevel === 'high')
              .map(e => `  ${e.method} ${e.fullUrl || e.path}`)
              .join('\n')
        }]
      };
    }

    case 'get_endpoints': {
      if (endpoints.length === 0) {
        return { content: [{ type: 'text', text: '暂无端点数据。请先运行 scan_url。' }] };
      }

      const text = endpoints.map((ep, i) =>
        `[${i}] [${ep.riskLevel.toUpperCase()}] ${ep.method} ${ep.fullUrl || ep.path} | tags: ${ep.tags.join(',')}`
      ).join('\n');

      return { content: [{ type: 'text', text: `共 ${endpoints.length} 个端点:\n\n${text}` }] };
    }

    case 'get_high_risk_endpoints': {
      const highRisk = endpoints.filter(e => e.riskLevel === 'high');
      if (highRisk.length === 0) {
        return { content: [{ type: 'text', text: '未发现高风险端点。' }] };
      }

      const text = highRisk.map((ep, i) =>
        `[${i}] ${ep.method} ${ep.fullUrl || ep.path} | ${ep.sourceFile} | tags: ${ep.tags.join(',')}`
      ).join('\n');

      return { content: [{ type: 'text', text: `高风险端点 (${highRisk.length}):\n\n${text}` }] };
    }

    case 'fuzz_endpoint': {
      let targetEndpoint: EndpointInfo | undefined;

      if (args.endpoint_index !== undefined && endpoints[args.endpoint_index]) {
        targetEndpoint = endpoints[args.endpoint_index];
      } else if (args.url) {
        targetEndpoint = {
          id: 'manual',
          url: args.url,
          method: args.method || 'GET',
          path: args.url,
          baseUrl: new URL(args.url).origin,
          fullUrl: args.url,
          headers: {},
          parameters: [],
          sourceFile: 'manual',
          riskLevel: 'medium',
          tags: []
        };
      }

      if (!targetEndpoint) {
        return { content: [{ type: 'text', text: 'ERROR: 需要指定 endpoint_index 或 url' }] };
      }

      const cfg = getConfig();
      const config: FuzzConfig = {
        concurrentRequests: cfg.concurrentRequests,
        timeout: cfg.timeout,
        subdomains: [],
        userToken: cfg.userToken,
        testAuthBypass: true,
        testIdor: true,
        testIdorBody: true,
        testParamInject: true,
        testSqlInject: true,
        testNoSqlInject: true,
        testSsrf: true,
        testMassAssignment: true,
        testBusinessLogic: true,
        testInterfaceAbuse: true,
        testRaceCondition: true,
        testSignBypass: true,
        pathVariants: true,
        testHorizontal: false
      };

      log(`Fuzzing: ${targetEndpoint.fullUrl || targetEndpoint.url}`);

      const result = await runFuzz(targetEndpoint, config, (progress) => {
        log(`  [${progress.phase}] ${progress.message}`);
      });

      fuzzResults.push(result);

      const failures = result.tests.filter(t => t.status === 'failed');
      const findings = failures.map(f => `- ${f.finding || f.description}`).join('\n');

      return {
        content: [{
          type: 'text',
          text: `Fuzz 测试完成: ${targetEndpoint.method} ${targetEndpoint.fullUrl}\n` +
            `- 总测试: ${result.tests.length} 项\n` +
            `- 通过: ${result.tests.filter(t => t.status === 'passed').length}\n` +
            `- 漏洞: ${failures.length}\n` +
            `- 综合风险: ${result.vulnerabilityLevel}\n` +
            (findings ? `\n发现:\n${findings}` : '\n未发现漏洞')
        }]
      };
    }

    case 'horizontal_fuzz': {
      const subdomains: string[] = args.subdomains || [];
      if (subdomains.length === 0) {
        return { content: [{ type: 'text', text: 'ERROR: subdomains is required' }] };
      }

      if (endpoints.length === 0) {
        return { content: [{ type: 'text', text: '暂无端点，请先运行 scan_url' }] };
      }

      const cfg = getConfig();
      const config: FuzzConfig = {
        concurrentRequests: cfg.concurrentRequests,
        timeout: cfg.timeout,
        subdomains,
        userToken: cfg.userToken,
        testAuthBypass: true,
        testIdor: true,
        testIdorBody: true,
        testParamInject: true,
        testSqlInject: true,
        testNoSqlInject: true,
        testSsrf: true,
        testMassAssignment: true,
        testBusinessLogic: true,
        testInterfaceAbuse: true,
        testRaceCondition: true,
        testSignBypass: true,
        pathVariants: true,
        testHorizontal: true
      };

      const allResults: FuzzResult[] = [];
      const vulnHosts = new Set<string>();

      for (const ep of endpoints) {
        log(`Horizontal Fuzz: ${ep.path}`);
        const results = await runHorizontalFuzz(ep, subdomains, config, () => {});
        allResults.push(...results);

        for (const r of results) {
          if (r.overallVulnerable) {
            vulnHosts.add(r.targetHost);
          }
        }
      }

      fuzzResults.push(...allResults);

      return {
        content: [{
          type: 'text',
          text: `横向 Fuzz 完成\n` +
            `- 测试端点: ${endpoints.length} 个\n` +
            `- 测试子域名: ${subdomains.length} 个\n` +
            `- 总测试结果: ${allResults.length}\n` +
            `- 发现脆弱子域名: ${vulnHosts.size} 个\n` +
            (vulnHosts.size > 0 ? `\n脆弱子域名:\n${Array.from(vulnHosts).map(h => `  - ${h}`).join('\n')}` : '')
        }]
      };
    }

    case 'generate_report': {
      const format = args.format || 'markdown';
      const content = generateReport(format);

      return {
        content: [{
          type: 'text',
          text: content.length > 5000
            ? content.slice(0, 5000) + '\n...(truncated)'
            : content
        }]
      };
    }

    case 'get_scan_status': {
      return {
        content: [{
          type: 'text',
          text: `JS API Hunter 状态\n` +
            `- 目标: ${targetUrl || '未扫描'}\n` +
            `- 发现的端点: ${endpoints.length}\n` +
            `- Fuzz 结果: ${fuzzResults.length}\n` +
            `- 发现漏洞: ${fuzzResults.filter(r => r.overallVulnerable).length}`
        }]
      };
    }

    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
  }
}

function generateReport(format: string): string {
  if (format === 'json') {
    return JSON.stringify({
      target: targetUrl,
      scanTime: new Date().toISOString(),
      totalEndpoints: endpoints.length,
      endpoints: endpoints.map(e => ({
        method: e.method,
        url: e.fullUrl,
        risk: e.riskLevel,
        tags: e.tags
      })),
      fuzzResults: fuzzResults.map(r => ({
        endpoint: r.endpoint.fullUrl,
        targetHost: r.targetHost,
        vulnerable: r.overallVulnerable,
        level: r.vulnerabilityLevel,
        findings: r.tests.filter(t => t.status === 'failed').map(t => t.finding)
      }))
    }, null, 2);
  }

  // markdown
  let md = `# JS API Hunter - 扫描报告\n\n`;
  md += `**目标**: ${targetUrl}\n`;
  md += `**扫描时间**: ${new Date().toISOString()}\n`;
  md += `**发现端点**: ${endpoints.length} 个\n\n`;

  md += `## API 端点\n\n| Method | URL | 风险 | 标签 |\n|---|---|---|---|\n`;
  for (const ep of endpoints) {
    md += `| ${ep.method} | ${ep.fullUrl || ep.path} | ${ep.riskLevel} | ${ep.tags.join(',')} |\n`;
  }

  if (fuzzResults.length > 0) {
    md += `\n## Fuzz 测试结果\n\n`;
    const vulnResults = fuzzResults.filter(r => r.overallVulnerable);
    if (vulnResults.length > 0) {
      md += `### 发现的漏洞 (${vulnResults.length})\n\n`;
      for (const r of vulnResults) {
        md += `#### ${r.endpoint.method} ${r.endpoint.fullUrl}\n`;
        md += `- **主机**: ${r.targetHost}\n`;
        md += `- **风险等级**: ${r.vulnerabilityLevel}\n`;
        const findings = r.tests.filter(t => t.status === 'failed');
        for (const f of findings) {
          md += `- ${f.finding || f.description}\n`;
        }
        md += '\n';
      }
    } else {
      md += `未发现漏洞。\n`;
    }
  }

  return md;
}

// 如果直接运行此文件，启动 stdio MCP 服务器
if (require.main === module) {
  startStdioServer();
}
