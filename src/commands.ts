import * as vscode from 'vscode';
import { ScanContext, EndpointInfo, FuzzConfig, FuzzResult, ReportFormat } from './types';
import { EndpointTreeProvider } from './tree/endpointTree';
import { collectJsFiles } from './collector/collector';
import { parseEndpoints } from './parser/parser';
import { assembleRequests, verifyEndpoints, toCurl, toPythonRequests } from './assembler/assembler';
import { runFuzz, runHorizontalFuzz } from './fuzzer/fuzzer';
import { FuzzerPanel } from './webview/fuzzerPanel';
import { analyzeSignatures, generateConsoleScript } from './signer/signer';
import { extractSecrets } from './secrets/secrets';
import { enumerateSubdomains, extractRootDomain, DEFAULT_SUBDOMAIN_PREFIXES } from './recon/subdomains';

export function registerCommands(
  context: vscode.ExtensionContext,
  scanContext: ScanContext,
  treeProvider: EndpointTreeProvider
) {
  // ========== 1. 新建扫描 ==========
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
    scanContext.secrets = [];
    scanContext.subdomains = [];
    scanContext.fuzzResults = [];

    const cfg = vscode.workspace.getConfiguration('jsApiHunter');
    const verifyEnabled = cfg.get('verifyEndpoints', true);
    const token = cfg.get<string>('userToken', '').trim() || undefined;

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'JS API Hunter',
      cancellable: true
    }, async (progress, tokenCancel) => {
      // Phase 1: 收集 JS
      progress.report({ message: '正在收集 JS 文件...' });
      scanContext.progress = { phase: 'collecting', jsFilesFound: 0, endpointsFound: 0, message: '收集 JS 文件中...' };
      treeProvider.refresh();

      try {
        scanContext.jsFiles = await collectJsFiles(url, (count) => {
          scanContext.progress.jsFilesFound = count;
          scanContext.progress.message = `已收集 ${count} 个 JS 文件`;
          progress.report({ message: `收集 JS 文件: ${count} 个`, increment: 25 });
          treeProvider.refresh();
        });
      } catch (err: any) {
        vscode.window.showErrorMessage(`JS 收集失败: ${err.message}`);
        return;
      }

      if (tokenCancel.isCancellationRequested) { return; }

      // Phase 2: 解析端点
      progress.report({ message: '正在解析端点...' });
      scanContext.progress = { phase: 'parsing', jsFilesFound: scanContext.jsFiles.length, endpointsFound: 0, message: '解析端点中...' };
      treeProvider.refresh();

      scanContext.endpoints = parseEndpoints(scanContext.jsFiles);
      scanContext.progress.endpointsFound = scanContext.endpoints.length;
      treeProvider.refresh();

      if (tokenCancel.isCancellationRequested) { return; }

      // Phase 3: 拼装请求
      progress.report({ message: '正在拼装完整请求...' });
      scanContext.progress = { phase: 'assembling', jsFilesFound: scanContext.jsFiles.length, endpointsFound: scanContext.endpoints.length, message: '拼装请求中...' };
      assembleRequests(scanContext.endpoints, scanContext.jsFiles);
      treeProvider.refresh();

      if (tokenCancel.isCancellationRequested) { return; }

      // Phase 4: 提取敏感信息
      progress.report({ message: '正在提取敏感信息...' });
      scanContext.secrets = extractSecrets(scanContext.jsFiles, scanContext.targetUrl);
      treeProvider.refresh();

      if (tokenCancel.isCancellationRequested) { return; }

      // Phase 5: 重放验证
      if (verifyEnabled && scanContext.endpoints.length > 0) {
        progress.report({ message: '正在重放验证端点...' });
        scanContext.progress = { phase: 'fuzzing', jsFilesFound: scanContext.jsFiles.length, endpointsFound: scanContext.endpoints.length, message: '重放验证中...' };
        treeProvider.refresh();
        await verifyEndpoints(scanContext.endpoints, token, 10000);
        treeProvider.refresh();
      }

      // 完成
      progress.report({ message: '扫描完成', increment: 100 });
      scanContext.progress = { phase: 'done', jsFilesFound: scanContext.jsFiles.length, endpointsFound: scanContext.endpoints.length, message: '扫描完成' };
      treeProvider.refresh();

      const reachable = scanContext.endpoints.filter(e => e.isReachable).length;
      vscode.window.showInformationMessage(
        `扫描完成: 发现 ${scanContext.endpoints.length} 个端点、` +
        `${scanContext.secrets.length} 条敏感信息、` +
        `${reachable} 个端点可验证`
      );
    });
  });

  // ========== 2. 刷新 / 清空 ==========
  const refreshCmd = vscode.commands.registerCommand('jsApiHunter.refresh', () => {
    treeProvider.refresh();
  });

  const clearCmd = vscode.commands.registerCommand('jsApiHunter.clear', () => {
    scanContext.jsFiles = [];
    scanContext.endpoints = [];
    scanContext.secrets = [];
    scanContext.subdomains = [];
    scanContext.fuzzResults = [];
    scanContext.targetUrl = '';
    scanContext.progress = { phase: 'idle', jsFilesFound: 0, endpointsFound: 0, message: '就绪' };
    treeProvider.refresh();
    vscode.window.showInformationMessage('结果已清空');
  });

  // ========== 3. 端点详情 ==========
  const detailCmd = vscode.commands.registerCommand('jsApiHunter.viewEndpointDetail', (endpoint) => {
    const panel = vscode.window.createWebviewPanel(
      'endpointDetail',
      `${endpoint.method} ${endpoint.path}`,
      vscode.ViewColumn.Two,
      { enableScripts: false }
    );
    panel.webview.html = getEndpointDetailHtml(endpoint);
  });

  const copyCmd = vscode.commands.registerCommand('jsApiHunter.copyEndpoint', (arg: any) => {
    const endpoint = arg?.endpoint || arg;
    vscode.env.clipboard.writeText(`${endpoint.method} ${endpoint.fullUrl}`);
    vscode.window.showInformationMessage('已复制完整请求 URL');
  });

  const copyCurlCmd = vscode.commands.registerCommand('jsApiHunter.copyAsCurl', (arg: any) => {
    const endpoint = arg?.endpoint || arg;
    const token = vscode.workspace.getConfiguration('jsApiHunter').get<string>('userToken', '').trim() || undefined;
    vscode.env.clipboard.writeText(toCurl(endpoint, token));
    vscode.window.showInformationMessage('已复制 cURL 命令');
  });

  const copyPythonCmd = vscode.commands.registerCommand('jsApiHunter.copyAsPython', (arg: any) => {
    const endpoint = arg?.endpoint || arg;
    const token = vscode.workspace.getConfiguration('jsApiHunter').get<string>('userToken', '').trim() || undefined;
    vscode.env.clipboard.writeText(toPythonRequests(endpoint, token));
    vscode.window.showInformationMessage('已复制 Python requests 脚本');
  });

  // ========== 4. 导出结果 ==========
  const exportCmd = vscode.commands.registerCommand('jsApiHunter.exportResults', async () => {
    if (scanContext.endpoints.length === 0) {
      vscode.window.showWarningMessage('没有可导出的结果');
      return;
    }

    const format = await vscode.window.showQuickPick([
      { label: 'JSON', value: 'json' },
      { label: 'Markdown', value: 'markdown' },
      { label: 'HTML', value: 'html' },
      { label: 'CSV (端点矩阵)', value: 'csv' },
      { label: 'SRC 漏洞报告模板', value: 'src' }
    ], { placeHolder: '选择导出格式' }) as { label: string; value: ReportFormat } | undefined;

    if (!format) { return; }

    const ext = format.value === 'src' ? 'md' : format.value;
    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(`js-api-hunter-results.${ext}`),
      filters: ext === 'json' ? { 'JSON': ['json'] }
        : ext === 'html' ? { 'HTML': ['html'] }
          : ext === 'csv' ? { 'CSV': ['csv'] }
            : { 'Markdown': ['md'] }
    });
    if (!uri) { return; }

    const content = formatExport(scanContext, format.value);
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf-8'));
    vscode.window.showInformationMessage(`结果已导出到 ${uri.fsPath}`);
  });

  // ========== 5. Fuzz 单个端点 ==========
  const fuzzCmd = vscode.commands.registerCommand('jsApiHunter.fuzzEndpoint', async (arg: any) => {
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

    const token = await getUserToken();
    const comparisonToken = await getComparisonToken();
    const config = buildFuzzConfig(token, comparisonToken);
    const panel = FuzzerPanel.createOrShow();

    const userSubdomains = await vscode.window.showInputBox({
      prompt: '输入横向测试子域名（逗号分隔，留空只测垂直）',
      placeHolder: 'test.example.com,dev.example.com'
    });

    if (userSubdomains) {
      config.subdomains = userSubdomains.split(',').map(s => s.trim()).filter(Boolean);
      config.testHorizontal = config.subdomains.length > 0;
    }

    const result = await runFuzz(endpoint, config, (progress) => {
      panel.updateProgress(progress);
    });

    panel.addResult(result);
    scanContext.fuzzResults.push(result);
    treeProvider.refresh();

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

  // ========== 6. 批量横向 Fuzz ==========
  const horizontalFuzzCmd = vscode.commands.registerCommand('jsApiHunter.horizontalFuzz', async () => {
    if (scanContext.endpoints.length === 0) {
      vscode.window.showWarningMessage('请先扫描获取端点');
      return;
    }

    let subdomains: string[] = [];
    if (scanContext.subdomains.length > 0) {
      const useStored = await vscode.window.showQuickPick(
        ['使用已收集的子域名', '手动输入子域名'],
        { placeHolder: '选择子域名来源' }
      );
      if (!useStored) { return; }
      if (useStored === '使用已收集的子域名') {
        subdomains = scanContext.subdomains.filter(s => s.isAlive).map(s => s.host);
      }
    }

    if (subdomains.length === 0) {
      const subdomainInput = await vscode.window.showInputBox({
        prompt: '输入子域名列表（逗号分隔）',
        placeHolder: 'test.example.com,dev.example.com,staging.example.com'
      });
      if (!subdomainInput) { return; }
      subdomains = subdomainInput.split(',').map(s => s.trim()).filter(Boolean);
    }

    const token = await getUserToken();
    const config = buildFuzzConfig(token);
    config.testHorizontal = true;
    config.pathVariants = vscode.workspace.getConfiguration('jsApiHunter').get('pathVariants', true);

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

  // ========== 7. 签名分析 ==========
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
    vscode.workspace.openTextDocument({
      content: script,
      language: 'javascript'
    }).then(doc => vscode.window.showTextDocument(doc, vscode.ViewColumn.Two));

    vscode.window.showInformationMessage(
      `发现 ${signatures.length} 个签名/加密逻辑，已生成 Console 调用脚本`
    );
  });

  // ========== 8. 子域名枚举 ==========
  const enumSubdomainsCmd = vscode.commands.registerCommand('jsApiHunter.enumerateSubdomains', async () => {
    if (!scanContext.targetUrl) {
      vscode.window.showWarningMessage('请先扫描目标');
      return;
    }

    const rootDomain = extractRootDomain(scanContext.targetUrl);
    if (!rootDomain) {
      vscode.window.showWarningMessage('无法提取根域名');
      return;
    }

    const cfg = vscode.workspace.getConfiguration('jsApiHunter');
    const customPrefixes = cfg.get<string[]>('subdomainPrefixes', DEFAULT_SUBDOMAIN_PREFIXES);

    const prefixInput = await vscode.window.showInputBox({
      prompt: `子域名前缀（逗号分隔，根域名: ${rootDomain}）`,
      value: customPrefixes.join(','),
      placeHolder: 'test,dev,staging,admin,api'
    });
    if (!prefixInput) { return; }
    const prefixes = prefixInput.split(',').map(s => s.trim()).filter(Boolean);

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: '子域名枚举',
      cancellable: true
    }, async (progress, token) => {
      scanContext.subdomains = await enumerateSubdomains(rootDomain, prefixes, (host, info) => {
        progress.report({ message: `${host} ${info.isAlive ? '✓' : '✗'}` });
        treeProvider.refresh();
      });

      const alive = scanContext.subdomains.filter(s => s.isAlive);
      vscode.window.showInformationMessage(
        `子域名枚举完成: ${alive.length}/${scanContext.subdomains.length} 个存活`
      );
      treeProvider.refresh();
    });
  });

  // ========== 9. 敏感信息面板 ==========
  const showSecretsCmd = vscode.commands.registerCommand('jsApiHunter.showSecrets', () => {
    if (scanContext.secrets.length === 0) {
      vscode.window.showInformationMessage('未发现敏感信息，请先扫描');
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'secretsPanel',
      'JS API Hunter - 敏感信息',
      vscode.ViewColumn.Two,
      { enableScripts: false }
    );
    panel.webview.html = getSecretsHtml(scanContext.secrets);
  });

  // ========== 10. 重放验证 ==========
  const verifyCmd = vscode.commands.registerCommand('jsApiHunter.verifyEndpoints', async () => {
    if (scanContext.endpoints.length === 0) {
      vscode.window.showWarningMessage('请先扫描获取端点');
      return;
    }
    const token = await getUserToken();
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: '重放验证端点'
    }, async (progress) => {
      progress.report({ message: '正在探测...' });
      await verifyEndpoints(scanContext.endpoints, token, 10000);
      const reachable = scanContext.endpoints.filter(e => e.isReachable).length;
      vscode.window.showInformationMessage(`验证完成: ${reachable}/${scanContext.endpoints.length} 个端点可达`);
      treeProvider.refresh();
    });
  });

  // ========== 11. MCP 配置引导 ==========
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

    vscode.env.clipboard.writeText(JSON.stringify(mcpConfig, null, 2));
    vscode.window.showInformationMessage('MCP 配置已复制到剪贴板');
  });

  context.subscriptions.push(
    scanCmd, refreshCmd, clearCmd, detailCmd, copyCmd, copyCurlCmd, copyPythonCmd,
    exportCmd, fuzzCmd, horizontalFuzzCmd, signAnalyzeCmd, enumSubdomainsCmd,
    showSecretsCmd, verifyCmd, mcpSetupCmd
  );
}

/** 获取用户 Token：优先配置，其次弹窗输入 */
async function getUserToken(): Promise<string | undefined> {
  const cfg = vscode.workspace.getConfiguration('jsApiHunter');
  const configured = cfg.get<string>('userToken', '').trim();
  if (configured) { return configured; }

  const input = await vscode.window.showInputBox({
    prompt: '输入测试 Token（Bearer xxx，留空则测试裸奔）',
    placeHolder: 'Bearer eyJhbGciOiJIUzI1NiIs...',
    password: true
  });
  return input?.trim() || undefined;
}

/** 获取第二个账号 Token，用于 IDOR 两账号对比 */
async function getComparisonToken(): Promise<string | undefined> {
  const input = await vscode.window.showInputBox({
    prompt: '输入第二个账号 Token（用于 IDOR 两账号对比，留空跳过）',
    placeHolder: 'Bearer eyJhbGciOiJIUzI1NiIs...',
    password: true
  });
  return input?.trim() || undefined;
}

/** 从 VS Code 配置构建 FuzzConfig */
function buildFuzzConfig(token?: string, comparisonToken?: string): FuzzConfig {
  const cfg = vscode.workspace.getConfiguration('jsApiHunter');
  return {
    concurrentRequests: cfg.get('concurrentRequests', 10),
    timeout: cfg.get('timeout', 30000),
    subdomains: [],
    userToken: token,
    comparisonToken,
    testAuthBypass: cfg.get('testAuthBypass', true),
    testIdor: cfg.get('testIdor', true),
    testIdorBody: cfg.get('testIdorBody', true),
    testParamInject: cfg.get('testParamInject', true),
    testSqlInject: cfg.get('testSqlInject', true),
    testNoSqlInject: cfg.get('testNoSqlInject', true),
    testSsrf: cfg.get('testSsrf', true),
    testMassAssignment: cfg.get('testMassAssignment', true),
    testBusinessLogic: cfg.get('testBusinessLogic', true),
    testInterfaceAbuse: cfg.get('testInterfaceAbuse', true),
    testRaceCondition: cfg.get('testRaceCondition', true),
    testSignBypass: cfg.get('testSignBypass', true),
    pathVariants: cfg.get('pathVariants', true),
    testHorizontal: false
  };
}

function getEndpointDetailHtml(endpoint: any): string {
  const verifyInfo = endpoint.isReachable !== undefined
    ? `<tr><td>验证状态</td><td>${endpoint.isReachable ? '✅ 可达' : '❌ 不可达'} (${endpoint.verifyStatus || '-'})</td></tr>`
    : '';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head><body>
<h2>${endpoint.method} ${endpoint.path}</h2>
<table>
<tr><td>完整URL</td><td><code>${endpoint.fullUrl}</code></td></tr>
<tr><td>baseURL</td><td><code>${endpoint.baseUrl}</code></td></tr>
<tr><td>来源文件</td><td><code>${endpoint.sourceFile}</code></td></tr>
<tr><td>风险等级</td><td>${endpoint.riskLevel}</td></tr>
<tr><td>标签</td><td>${endpoint.tags.join(', ')}</td></tr>
${verifyInfo}
</table>
<h3>Headers</h3>
<pre>${JSON.stringify(endpoint.headers, null, 2)}</pre>
</body></html>`;
}

function getSecretsHtml(secrets: any[]): string {
  const rows = secrets.map(s => `
<tr>
  <td>${s.type}</td>
  <td>${s.name}</td>
  <td><code>${s.value}</code></td>
  <td>${s.sourceFile}</td>
  <td>${s.riskLevel}</td>
</tr>`).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body{font-family:Arial,sans-serif;margin:20px}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#2d2d2d;color:#fff}
.high{color:#e53935;font-weight:bold}
.medium{color:#fb8c00;font-weight:bold}
</style>
</head><body>
<h2>发现的敏感信息 (${secrets.length})</h2>
<table>
<tr><th>类型</th><th>名称</th><th>值（已掩码）</th><th>来源文件</th><th>风险</th></tr>
${rows}
</table>
</body></html>`;
}

function formatExport(ctx: ScanContext, format: ReportFormat): string {
  if (format === 'json') {
    return JSON.stringify({
      target: ctx.targetUrl,
      scanTime: new Date().toISOString(),
      totalEndpoints: ctx.endpoints.length,
      totalSecrets: ctx.secrets.length,
      totalSubdomains: ctx.subdomains.length,
      totalFuzzResults: ctx.fuzzResults.length,
      vulnerable: ctx.fuzzResults.filter(r => r.overallVulnerable).length,
      endpoints: ctx.endpoints.map(ep => ({
        method: ep.method,
        url: ep.fullUrl,
        baseUrl: ep.baseUrl,
        risk: ep.riskLevel,
        tags: ep.tags,
        sourceFile: ep.sourceFile,
        isReachable: ep.isReachable,
        verifyStatus: ep.verifyStatus
      })),
      secrets: ctx.secrets.map(s => ({
        type: s.type,
        name: s.name,
        value: s.value,
        sourceFile: s.sourceFile,
        risk: s.riskLevel
      })),
      subdomains: ctx.subdomains,
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
<p><strong>发现端点:</strong> ${ctx.endpoints.length} 个 | <strong>敏感信息:</strong> ${ctx.secrets.length} 条 | <strong>子域名:</strong> ${ctx.subdomains.filter(s => s.isAlive).length}/${ctx.subdomains.length}</p>
<h2>API 端点</h2>
<table><tr><th>Method</th><th>URL</th><th>风险</th><th>标签</th><th>可达</th><th>来源</th></tr>`;
    for (const ep of ctx.endpoints) {
      html += `<tr><td>${ep.method}</td><td>${ep.fullUrl}</td><td class="${ep.riskLevel}">${ep.riskLevel}</td><td>${ep.tags.join(', ')}</td><td>${ep.isReachable ? '✓' : '✗'} ${ep.verifyStatus || ''}</td><td>${ep.sourceFile}</td></tr>`;
    }
    html += '</table>';

    if (ctx.secrets.length > 0) {
      html += `<h2>敏感信息</h2><table><tr><th>类型</th><th>名称</th><th>值</th><th>来源</th></tr>`;
      for (const s of ctx.secrets) {
        html += `<tr><td>${s.type}</td><td>${s.name}</td><td><code>${s.value}</code></td><td>${s.sourceFile}</td></tr>`;
      }
      html += '</table>';
    }

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

  if (format === 'csv') {
    const lines: string[] = ['method,fullUrl,baseUrl,risk,tags,sourceFile,isReachable,verifyStatus'];
    for (const ep of ctx.endpoints) {
      lines.push(csvRow([
        ep.method,
        ep.fullUrl,
        ep.baseUrl,
        ep.riskLevel,
        ep.tags.join(';'),
        ep.sourceFile,
        ep.isReachable === undefined ? '' : String(ep.isReachable),
        ep.verifyStatus === undefined ? '' : String(ep.verifyStatus)
      ]));
    }
    lines.push('');
    lines.push('endpoint,host,testType,status,description,responseStatus,finding');
    for (const r of ctx.fuzzResults) {
      for (const t of r.tests) {
        lines.push(csvRow([
          `${r.endpoint.method} ${r.endpoint.fullUrl}`,
          r.targetHost,
          t.testType,
          t.status,
          t.description,
          t.responseStatus === undefined ? '' : String(t.responseStatus),
          t.finding || ''
        ]));
      }
    }
    return lines.join('\n');
  }

  if (format === 'src') {
    const vulnResults = ctx.fuzzResults.filter(r => r.overallVulnerable);
    if (vulnResults.length === 0) {
      return '# JS API Hunter - SRC 漏洞报告\n\n未发现可导出的漏洞。';
    }
    let md = `# JS API Hunter - SRC 漏洞报告\n\n`;
    md += `**目标**: ${ctx.targetUrl}\n`;
    md += `**扫描时间**: ${new Date().toISOString()}\n\n`;

    for (let i = 0; i < vulnResults.length; i++) {
      const r = vulnResults[i];
      const findings = r.tests.filter(t => t.status === 'failed');
      md += `## 漏洞 ${i + 1}: ${r.endpoint.method} ${r.endpoint.fullUrl}\n\n`;
      md += `**风险等级**: ${r.vulnerabilityLevel.toUpperCase()}\n\n`;
      md += `**目标主机**: ${r.targetHost}\n\n`;
      md += `### 复现步骤\n\n`;
      for (const f of findings) {
        md += `1. 发送请求: \`${f.requestInfo}\`\n`;
        if (f.responseStatus) {
          md += `2. 观察到响应状态码: \`${f.responseStatus}\`\n`;
        }
        md += `3. 结论: ${f.finding || f.description}\n\n`;
      }
      md += `### 影响范围\n\n`;
      md += `可能导致未授权访问、数据泄露或权限提升。\n\n`;
      md += `### 修复建议\n\n`;
      md += `- 对所有环境统一鉴权中间件，避免测试/老系统裸奔\n`;
      md += `- 对管理接口增加角色校验\n`;
      md += `- 关闭生产/测试环境的 source map 与调试接口\n\n`;
      md += `---\n\n`;
    }
    return md;
  }

  // markdown
  let md = `# JS API Hunter - 扫描报告\n\n`;
  md += `**目标**: ${ctx.targetUrl}\n`;
  md += `**扫描时间**: ${new Date().toISOString()}\n`;
  md += `**发现端点**: ${ctx.endpoints.length} 个\n`;
  md += `**敏感信息**: ${ctx.secrets.length} 条\n`;
  md += `**存活子域名**: ${ctx.subdomains.filter(s => s.isAlive).length}/${ctx.subdomains.length}\n`;
  if (ctx.fuzzResults.length > 0) {
    md += `**Fuzz 结果**: ${ctx.fuzzResults.length} 个 | **漏洞**: ${ctx.fuzzResults.filter(r => r.overallVulnerable).length} 个\n`;
  }
  md += `\n## API 端点\n\n| Method | URL | 风险 | 标签 | 可达 | 来源 |\n|---|---|---|---|---|---|\n`;
  for (const ep of ctx.endpoints) {
    md += `| ${ep.method} | ${ep.fullUrl} | ${ep.riskLevel} | ${ep.tags.join(', ')} | ${ep.isReachable === undefined ? '-' : (ep.isReachable ? '✓' : '✗')} | ${ep.sourceFile} |\n`;
  }

  if (ctx.secrets.length > 0) {
    md += `\n## 敏感信息\n\n| 类型 | 名称 | 值 | 来源 |\n|---|---|---|---|\n`;
    for (const s of ctx.secrets) {
      md += `| ${s.type} | ${s.name} | ${s.value} | ${s.sourceFile} |\n`;
    }
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

    // 横向 Fuzz 矩阵（PDF 第 7 章）
    const horizontalResults = ctx.fuzzResults.filter(r => r.targetHost && r.targetHost !== new URL(r.endpoint.fullUrl || r.endpoint.url || 'http://x').host);
    if (horizontalResults.length > 0) {
      md += `\n### 横向 Fuzz 矩阵\n\n`;
      md += `| 接口 \\ 域名 | 主站 | 横向目标 | 结果 |\n`;
      md += `|---|---|---|---|\n`;
      for (const r of horizontalResults) {
        const baseHost = new URL(r.endpoint.fullUrl || r.endpoint.url || 'http://x').host;
        const failed = r.tests.filter(t => t.status === 'failed');
        const result = failed.length > 0
          ? `⭐ ${failed.length} 个漏洞: ${failed.map(f => f.finding || f.description).join('; ').slice(0, 80)}`
          : '无漏洞';
        md += `| ${r.endpoint.method} ${r.endpoint.path} | ${baseHost} | ${r.targetHost} | ${result} |\n`;
      }
    }
  }
  return md;
}

function csvRow(values: string[]): string {
  return values.map(v => {
    const s = String(v ?? '').replace(/"/g, '""');
    return s.includes(',') || s.includes('\n') || s.includes('"') ? `"${s}"` : s;
  }).join(',');
}
