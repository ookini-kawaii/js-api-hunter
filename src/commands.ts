import * as vscode from 'vscode';
import { ScanContext, EndpointInfo, FuzzConfig } from './types';
import { EndpointTreeProvider } from './tree/endpointTree';
import { collectJsFiles } from './collector/collector';
import { parseEndpoints } from './parser/parser';
import { assembleRequests } from './assembler/assembler';
import { runFuzz, runHorizontalFuzz } from './fuzzer/fuzzer';
import { FuzzerPanel } from './webview/fuzzerPanel';
import { analyzeSignatures, generateConsoleScript } from './signer/signer';

export function registerCommands(
  context: vscode.ExtensionContext,
  scanContext: ScanContext,
  treeProvider: EndpointTreeProvider
) {
  // 新建扫描
  const scanCmd = vscode.commands.registerCommand('jsApiHunter.scan', async () => {
    const url = await vscode.window.showInputBox({
      prompt: '输入目标 URL',
      placeHolder: 'https://target.com',
      validateInput: (value) => {
        if (!value) { return '请输入 URL'; }
        try { new URL(value); return null; } catch { return '请输入有效 URL（以 http:// 或 https:// 开头）'; }
      }
    });

    if (!url) { return; }

    scanContext.targetUrl = url;
    scanContext.jsFiles = [];
    scanContext.endpoints = [];

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'JS API Hunter',
      cancellable: true
    }, async (progress, token) => {
      // Phase 1: 收集 JS 文件
      progress.report({ message: '正在收集 JS 文件...' });
      scanContext.progress = { phase: 'collecting', jsFilesFound: 0, endpointsFound: 0, message: '收集 JS 文件中...' };
      treeProvider.refresh();

      try {
        scanContext.jsFiles = await collectJsFiles(url, (count) => {
          scanContext.progress.jsFilesFound = count;
          scanContext.progress.message = `已收集 ${count} 个 JS 文件`;
          progress.report({ message: `收集 JS 文件: ${count} 个`, increment: 30 });
          treeProvider.refresh();
        });
      } catch (err: any) {
        if (err.message === 'cancelled') { return; }
        vscode.window.showErrorMessage(`JS 收集失败: ${err.message}`);
        return;
      }

      if (token.isCancellationRequested) { return; }

      // Phase 2: 解析端点
      progress.report({ message: '正在解析端点...' });
      scanContext.progress = { phase: 'parsing', jsFilesFound: scanContext.jsFiles.length, endpointsFound: 0, message: '解析端点中...' };
      treeProvider.refresh();

      scanContext.endpoints = parseEndpoints(scanContext.jsFiles);
      scanContext.progress.endpointsFound = scanContext.endpoints.length;
      treeProvider.refresh();

      // Phase 3: 拼装请求
      progress.report({ message: '正在拼装完整请求...' });
      scanContext.progress = { phase: 'assembling', jsFilesFound: scanContext.jsFiles.length, endpointsFound: scanContext.endpoints.length, message: '拼装请求中...' };
      assembleRequests(scanContext.endpoints, scanContext.jsFiles);
      treeProvider.refresh();

      // 完成
      progress.report({ message: '扫描完成', increment: 100 });
      scanContext.progress = { phase: 'done', jsFilesFound: scanContext.jsFiles.length, endpointsFound: scanContext.endpoints.length, message: '扫描完成' };
      treeProvider.refresh();

      vscode.window.showInformationMessage(
        `扫描完成: 发现 ${scanContext.endpoints.length} 个端点（来自 ${scanContext.jsFiles.length} 个 JS 文件）`
      );
    });
  });

  // 刷新
  const refreshCmd = vscode.commands.registerCommand('jsApiHunter.refresh', () => {
    treeProvider.refresh();
  });

  // 清空
  const clearCmd = vscode.commands.registerCommand('jsApiHunter.clear', () => {
    scanContext.jsFiles = [];
    scanContext.endpoints = [];
    scanContext.fuzzResults = [];
    scanContext.targetUrl = '';
    scanContext.progress = { phase: 'idle', jsFilesFound: 0, endpointsFound: 0, message: '就绪' };
    treeProvider.refresh();
    vscode.window.showInformationMessage('结果已清空');
  });

  // 查看端点详情
  const detailCmd = vscode.commands.registerCommand('jsApiHunter.viewEndpointDetail', (endpoint) => {
    const detail = new vscode.MarkdownString();
    detail.appendMarkdown(`## ${endpoint.method} ${endpoint.path}\n\n`);
    detail.appendMarkdown(`| 属性 | 值 |\n|---|---|\n`);
    detail.appendMarkdown(`| 完整 URL | \`${endpoint.fullUrl}\` |\n`);
    detail.appendMarkdown(`| 来源文件 | \`${endpoint.sourceFile}\` |\n`);
    detail.appendMarkdown(`| 风险等级 | ${endpoint.riskLevel} |\n`);
    detail.appendMarkdown(`| 标签 | ${endpoint.tags.join(', ')} |\n\n`);
    detail.appendMarkdown('### 请求 Headers\n\n```json\n' + JSON.stringify(endpoint.headers, null, 2) + '\n```');

    const panel = vscode.window.createWebviewPanel(
      'endpointDetail',
      `${endpoint.method} ${endpoint.path}`,
      vscode.ViewColumn.Two,
      { enableScripts: false }
    );
    panel.webview.html = getEndpointDetailHtml(endpoint);
  });

  // 复制端点
  const copyCmd = vscode.commands.registerCommand('jsApiHunter.copyEndpoint', (arg: any) => {
    const endpoint = arg?.endpoint || arg;
    vscode.env.clipboard.writeText(`${endpoint.method} ${endpoint.fullUrl}`);
    vscode.window.showInformationMessage('已复制完整请求 URL');
  });

  // 导出结果
  const exportCmd = vscode.commands.registerCommand('jsApiHunter.exportResults', async () => {
    if (scanContext.endpoints.length === 0) {
      vscode.window.showWarningMessage('没有可导出的结果');
      return;
    }

    const format = await vscode.window.showQuickPick(['json', 'markdown', 'html'], {
      placeHolder: '选择导出格式'
    });
    if (!format) { return; }

    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(`js-api-hunter-results.${format}`),
      filters: format === 'json'
        ? { 'JSON': ['json'] }
        : format === 'html'
          ? { 'HTML': ['html'] }
          : { 'Markdown': ['md'] }
    });
    if (!uri) { return; }

    const content = formatExport(scanContext, format);
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf-8'));
    vscode.window.showInformationMessage(`结果已导出到 ${uri.fsPath}`);
  });

  // Fuzz 单个端点
  const fuzzCmd = vscode.commands.registerCommand('jsApiHunter.fuzzEndpoint', async (arg: any) => {
    // 从 TreeView 右键菜单传过来的是 TreeItem，提取 endpoint
    let endpoint: EndpointInfo | undefined = arg?.endpoint || arg;

    if (!endpoint || !endpoint.fullUrl) {
      const picked = await vscode.window.showQuickPick(
        scanContext.endpoints.map(ep => ({
          label: `${ep.method} ${ep.path}`,
          description: ep.riskLevel,
          detail: ep.fullUrl || ep.url,
          endpoint: ep
        })),
        { placeHolder: '选择要测试的端点' }
      );
      if (!picked) { return; }
      endpoint = picked.endpoint;
    }

    const config = buildFuzzConfig();
    const panel = FuzzerPanel.createOrShow();

    const userSubdomains = await vscode.window.showInputBox({
      prompt: '输入横向测试子域名（逗号分隔，留空跳过）',
      placeHolder: 'test.example.com,dev.example.com'
    });

    if (userSubdomains) {
      config.subdomains = userSubdomains.split(',').map(s => s.trim()).filter(Boolean);
      config.testHorizontal = config.subdomains.length > 0;
    }

    // 运行垂直测试
    const result = await runFuzz(endpoint, config, (progress) => {
      panel.updateProgress(progress);
    });

    panel.addResult(result);
    scanContext.fuzzResults.push(result);
    treeProvider.refresh();

    // 横向 Fuzz
    if (config.testHorizontal) {
      panel.addLog(`开始横向 Fuzz: ${config.subdomains.join(', ')}`);
      const horizontalResults = await runHorizontalFuzz(endpoint, config.subdomains, config, (progress) => {
        panel.updateProgress(progress);
      });
      panel.addHorizontalResults(horizontalResults);
      scanContext.fuzzResults.push(...horizontalResults);

      const vulnHosts = horizontalResults.filter(r => r.overallVulnerable);
      if (vulnHosts.length > 0) {
        vscode.window.showWarningMessage(
          `横向 Fuzz 发现 ${vulnHosts.length} 个脆弱子域名: ${vulnHosts.map(r => r.targetHost).join(', ')}`
        );
      }
    }

    panel.setComplete();
  });

  // 批量横向 Fuzz
  const horizontalFuzzCmd = vscode.commands.registerCommand('jsApiHunter.horizontalFuzz', async () => {
    if (scanContext.endpoints.length === 0) {
      vscode.window.showWarningMessage('请先扫描获取端点');
      return;
    }

    const subdomainInput = await vscode.window.showInputBox({
      prompt: '输入子域名列表（逗号分隔）',
      placeHolder: 'test.example.com,dev.example.com,staging.example.com'
    });
    if (!subdomainInput) { return; }

    const subdomains = subdomainInput.split(',').map(s => s.trim()).filter(Boolean);
    const config = buildFuzzConfig();
    config.testHorizontal = true;

    const panel = FuzzerPanel.createOrShow();

    for (const ep of scanContext.endpoints) {
      panel.addLog(`横向测试: ${ep.method} ${ep.path}`);
      const results = await runHorizontalFuzz(ep, subdomains, config, (progress) => {
        panel.updateProgress(progress);
      });
      panel.addHorizontalResults(results);
      scanContext.fuzzResults.push(...results);

      const vulnHosts = results.filter(r => r.overallVulnerable);
      if (vulnHosts.length > 0) {
        panel.addLog(`  → ${ep.path}: ${vulnHosts.length} 个脆弱子域`);
      }
    }

    panel.setComplete();
    treeProvider.refresh();
  });

  // 签名分析
  const signAnalyzeCmd = vscode.commands.registerCommand('jsApiHunter.analyzeSignatures', () => {
    if (scanContext.jsFiles.length === 0) {
      vscode.window.showWarningMessage('请先扫描获取 JS 文件');
      return;
    }

    const signatures = analyzeSignatures(scanContext.jsFiles);

    if (signatures.length === 0) {
      vscode.window.showInformationMessage('未检测到签名/加密逻辑');
      return;
    }

    const script = generateConsoleScript(signatures);

    // 在新文档中打开
    vscode.workspace.openTextDocument({
      content: script,
      language: 'javascript'
    }).then(doc => vscode.window.showTextDocument(doc, vscode.ViewColumn.Two));

    vscode.window.showInformationMessage(
      `发现 ${signatures.length} 个签名/加密逻辑，已生成 Console 调用脚本`
    );
  });

  // 打开 MCP 配置引导
  const mcpSetupCmd = vscode.commands.registerCommand('jsApiHunter.setupMcp', () => {
    const mcpConfig = {
      mcpServers: {
        'js-api-hunter': {
          command: 'node',
          args: [context.extensionPath + '/out/mcp/server.js'],
          description: 'JS API Hunter - JS 接口自动发现与测试'
        }
      }
    };

    const configText = JSON.stringify(mcpConfig, null, 2);
    const guide = `# JS API Hunter - MCP 集成指南

将此配置添加到你的 Claude Code / Trae CN 配置文件中：

## Claude Code
将以下内容添加到 ~/.config/claude/claude_desktop_config.json 的 mcpServers 中：

\`\`\`json
${configText}
\`\`\`

## Trae CN
在 MCP 配置中添加此服务器。

配置完成后，Claude Code 可以调用以下工具：
- scan_url(url) - 扫描目标网站
- get_endpoints() - 获取发现的 API 端点
- get_high_risk_endpoints() - 获取高风险端点
- fuzz_endpoint(url) - 对端点执行安全测试
- horizontal_fuzz(subdomains) - 横向多域名测试
- generate_report(format) - 生成漏洞报告
- get_scan_status() - 查看扫描状态
`;

    vscode.workspace.openTextDocument({
      content: guide,
      language: 'markdown'
    }).then(doc => vscode.window.showTextDocument(doc, vscode.ViewColumn.Two));

    // 同时复制配置到剪贴板
    vscode.env.clipboard.writeText(JSON.stringify(mcpConfig, null, 2));
    vscode.window.showInformationMessage('MCP 配置已复制到剪贴板');
  });

  context.subscriptions.push(scanCmd, refreshCmd, clearCmd, detailCmd, copyCmd, exportCmd, fuzzCmd, horizontalFuzzCmd, signAnalyzeCmd, mcpSetupCmd);
}

/** 从 VS Code 配置构建 FuzzConfig */
function buildFuzzConfig(): FuzzConfig {
  const cfg = vscode.workspace.getConfiguration('jsApiHunter');
  return {
    concurrentRequests: cfg.get('concurrentRequests', 10),
    timeout: cfg.get('timeout', 30000),
    subdomains: [],
    testAuthBypass: true,
    testIdor: true,
    testParamInject: true,
    testSqlInject: true,
    testSsrf: true,
    testHorizontal: false
  };
}

function getEndpointDetailHtml(endpoint: any): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head><body>
<h2>${endpoint.method} ${endpoint.path}</h2>
<table>
<tr><td>完整URL</td><td><code>${endpoint.fullUrl}</code></td></tr>
<tr><td>来源文件</td><td><code>${endpoint.sourceFile}</code></td></tr>
<tr><td>风险等级</td><td>${endpoint.riskLevel}</td></tr>
<tr><td>标签</td><td>${endpoint.tags.join(', ')}</td></tr>
</table>
<h3>Headers</h3>
<pre>${JSON.stringify(endpoint.headers, null, 2)}</pre>
</body></html>`;
}

function formatExport(ctx: ScanContext, format: string): string {
  if (format === 'json') {
    return JSON.stringify({
      target: ctx.targetUrl,
      scanTime: new Date().toISOString(),
      totalEndpoints: ctx.endpoints.length,
      totalFuzzResults: ctx.fuzzResults.length,
      vulnerable: ctx.fuzzResults.filter(r => r.overallVulnerable).length,
      endpoints: ctx.endpoints.map(ep => ({
        method: ep.method,
        url: ep.fullUrl,
        risk: ep.riskLevel,
        tags: ep.tags,
        sourceFile: ep.sourceFile
      })),
      fuzzResults: ctx.fuzzResults.map(r => ({
        endpoint: `${r.endpoint.method} ${r.endpoint.fullUrl}`,
        targetHost: r.targetHost,
        vulnerable: r.overallVulnerable,
        level: r.vulnerabilityLevel,
        findings: r.tests.filter(t => t.status === 'failed').map(t => t.finding)
      }))
    }, null, 2);
  }

  if (format === 'html') {
    let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>JS API Hunter Report</title>
<style>body{font-family:Arial,sans-serif;margin:20px;max-width:1200px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px 12px;text-align:left}th{background:#2d2d2d;color:#fff}.high{color:#e53935;font-weight:bold}.medium{color:#fb8c00;font-weight:bold}.low{color:#43a047}.finding{background:#ffebee;border-left:4px solid #e53935;padding:8px 12px;margin:6px 0}
h2{border-bottom:2px solid #2d2d2d;padding-bottom:6px;margin-top:24px}
.stat{display:inline-block;padding:4px 16px;border-radius:4px;margin:4px;color:#fff;font-weight:bold}
.stat-high{background:#e53935}.stat-medium{background:#fb8c00}.stat-low{background:#43a047}
</style>
</head><body><h1>JS API Hunter - 扫描报告</h1>
<p><strong>目标:</strong> ${ctx.targetUrl}</p>
<p><strong>扫描时间:</strong> ${new Date().toISOString()}</p>
<p><strong>发现端点:</strong> ${ctx.endpoints.length} 个</p>
<h2>API 端点</h2>
<table><tr><th>Method</th><th>URL</th><th>风险</th><th>标签</th><th>来源</th></tr>`;
    for (const ep of ctx.endpoints) {
      html += `<tr><td>${ep.method}</td><td>${ep.fullUrl}</td><td class="${ep.riskLevel}">${ep.riskLevel}</td><td>${ep.tags.join(', ')}</td><td>${ep.sourceFile}</td></tr>`;
    }
    html += '</table>';

    // Fuzz 结果
    if (ctx.fuzzResults.length > 0) {
      const vulnResults = ctx.fuzzResults.filter(r => r.overallVulnerable);
      html += `<h2>Fuzz 测试结果</h2>
<p><span class="stat stat-high">漏洞: ${vulnResults.length}</span>
<span class="stat stat-low">总测试: ${ctx.fuzzResults.length}</span></p>`;

      if (vulnResults.length > 0) {
        html += '<h3>发现的漏洞</h3>';
        for (const r of vulnResults) {
          html += `<div class="finding">
<strong>${r.endpoint.method} ${r.endpoint.fullUrl}</strong> (${r.targetHost}) - ${r.vulnerabilityLevel.toUpperCase()}
<ul>`;
          for (const t of r.tests.filter(t => t.status === 'failed')) {
            html += `<li>${t.finding || t.description}</li>`;
          }
          html += '</ul></div>';
        }
      }
    }

    html += '</body></html>';
    return html;
  }

  // markdown
  let md = `# JS API Hunter - 扫描报告\n\n`;
  md += `**目标**: ${ctx.targetUrl}\n`;
  md += `**扫描时间**: ${new Date().toISOString()}\n`;
  md += `**发现端点**: ${ctx.endpoints.length} 个\n`;
  if (ctx.fuzzResults.length > 0) {
    md += `**Fuzz 结果**: ${ctx.fuzzResults.length} 个 | **漏洞**: ${ctx.fuzzResults.filter(r => r.overallVulnerable).length} 个\n`;
  }
  md += `\n## API 端点\n\n| Method | URL | 风险 | 标签 | 来源 |\n|---|---|---|---|---|\n`;
  for (const ep of ctx.endpoints) {
    md += `| ${ep.method} | ${ep.fullUrl} | ${ep.riskLevel} | ${ep.tags.join(', ')} | ${ep.sourceFile} |\n`;
  }

  if (ctx.fuzzResults.length > 0) {
    md += `\n## Fuzz 测试结果\n\n`;
    const vulnResults = ctx.fuzzResults.filter(r => r.overallVulnerable);
    if (vulnResults.length > 0) {
      md += `### 发现的漏洞 (${vulnResults.length})\n\n`;
      for (const r of vulnResults) {
        md += `#### ${r.endpoint.method} ${r.endpoint.fullUrl}\n`;
        md += `- **主机**: ${r.targetHost}\n`;
        md += `- **风险等级**: ${r.vulnerabilityLevel}\n`;
        for (const t of r.tests.filter(t => t.status === 'failed')) {
          md += `- ${t.finding || t.description}\n`;
        }
        md += '\n';
      }
    } else {
      md += `未发现漏洞。\n`;
    }
  }
  return md;
}
