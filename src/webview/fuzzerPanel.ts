import * as vscode from 'vscode';
import { EndpointInfo, FuzzResult, FuzzProgress, SingleTestResult } from '../types';

/**
 * Fuzzer WebView 面板
 * 展示测试进度和实时结果
 */
export class FuzzerPanel {
  public static currentPanel: FuzzerPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private _disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel) {
    this._panel = panel;
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
    this._panel.webview.html = this._getHtml();
  }

  public static createOrShow() {
    const column = vscode.ViewColumn.Two;

    if (FuzzerPanel.currentPanel) {
      FuzzerPanel.currentPanel._panel.reveal(column);
      return FuzzerPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'fuzzerPanel',
      'JS API Hunter - Fuzzer',
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true
      }
    );

    FuzzerPanel.currentPanel = new FuzzerPanel(panel);
    return FuzzerPanel.currentPanel;
  }

  public updateProgress(progress: FuzzProgress) {
    this._panel.webview.postMessage({ type: 'progress', data: progress });
  }

  public addResult(result: FuzzResult) {
    this._panel.webview.postMessage({ type: 'result', data: result });
  }

  public addHorizontalResults(results: FuzzResult[]) {
    for (const r of results) {
      this._panel.webview.postMessage({ type: 'result', data: r });
    }
  }

  public setComplete() {
    this._panel.webview.postMessage({ type: 'complete' });
  }

  public addLog(message: string) {
    this._panel.webview.postMessage({ type: 'log', data: message });
  }

  public dispose() {
    FuzzerPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      this._disposables.pop()!.dispose();
    }
  }

  private _getHtml(): string {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JS API Hunter - Fuzzer</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: var(--vscode-font-family, 'Segoe UI', sans-serif);
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      padding: 16px;
      font-size: 13px;
    }
    h3 { margin-bottom: 12px; color: var(--vscode-foreground); font-size: 14px; }
    .progress-bar {
      height: 6px;
      background: var(--vscode-progressBar-background);
      border-radius: 3px;
      overflow: hidden;
      margin-bottom: 12px;
    }
    .progress-fill {
      height: 100%;
      background: var(--vscode-progressBar-foreground);
      width: 0%;
      transition: width 0.3s;
    }
    .stats {
      display: flex;
      gap: 16px;
      margin-bottom: 16px;
      font-size: 12px;
    }
    .stat {
      padding: 4px 12px;
      border-radius: 4px;
      font-weight: 600;
    }
    .stat-passed { background: #1b5e20; color: #81c784; }
    .stat-failed { background: #b71c1c; color: #ef9a9a; }
    .stat-error { background: #e65100; color: #ffcc80; }
    .stat-pending { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
    .result-card {
      background: var(--vscode-textBlockQuote-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
      padding: 10px 14px;
      margin-bottom: 8px;
    }
    .result-endpoint {
      font-weight: 600;
      margin-bottom: 4px;
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 12px;
    }
    .result-tests {
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
    }
    .finding {
      margin-top: 6px;
      padding: 6px 10px;
      background: #b71c1c22;
      border-left: 3px solid #ef5350;
      border-radius: 3px;
      color: #ef9a9a;
      font-size: 12px;
    }
    .badge {
      display: inline-block;
      padding: 1px 8px;
      border-radius: 10px;
      font-size: 11px;
      font-weight: 600;
      margin-left: 8px;
    }
    .badge-high { background: #b71c1c; color: #fff; }
    .badge-medium { background: #e65100; color: #fff; }
    .badge-low { background: #33691e; color: #fff; }
    .host-tag {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      background: var(--vscode-badge-background);
      padding: 1px 6px;
      border-radius: 3px;
      margin-left: 8px;
    }
    .log-area {
      margin-top: 16px;
      padding: 10px;
      background: var(--vscode-textBlockQuote-background);
      border-radius: 6px;
      font-family: monospace;
      font-size: 11px;
      max-height: 200px;
      overflow-y: auto;
      color: var(--vscode-descriptionForeground);
    }
    .empty-state {
      text-align: center;
      padding: 40px;
      color: var(--vscode-descriptionForeground);
    }
  </style>
</head>
<body>
  <h3>Fuzzer 测试面板</h3>
  <div class="progress-bar">
    <div id="progress-fill" class="progress-fill"></div>
  </div>
  <div class="stats">
    <span id="stat-passed" class="stat stat-passed">通过: 0</span>
    <span id="stat-failed" class="stat stat-failed">漏洞: 0</span>
    <span id="stat-error" class="stat stat-error">错误: 0</span>
    <span id="stat-pending" class="stat stat-pending">待测试</span>
  </div>
  <div id="status-text" class="empty-state">等待开始测试...</div>
  <div id="results"></div>
  <div id="logs" class="log-area" style="display:none;">
    <div style="font-weight:600;margin-bottom:4px;">日志</div>
    <div id="log-content"></div>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    let passedCount = 0, failedCount = 0, errorCount = 0;
    let totalTests = 0, completedTests = 0;

    function updateStats() {
      document.getElementById('stat-passed').textContent = '通过: ' + passedCount;
      document.getElementById('stat-failed').textContent = '漏洞: ' + failedCount;
      document.getElementById('stat-error').textContent = '错误: ' + errorCount;
      document.getElementById('stat-pending').textContent = '待测试: ' + (totalTests - completedTests);

      const pct = totalTests > 0 ? Math.round((completedTests / totalTests) * 100) : 0;
      document.getElementById('progress-fill').style.width = pct + '%';
    }

    window.addEventListener('message', (event) => {
      const msg = event.data;

      switch (msg.type) {
        case 'progress': {
          totalTests = msg.data.total;
          completedTests = msg.data.completed;
          document.getElementById('status-text').textContent = msg.data.message;
          updateStats();
          break;
        }
        case 'result': {
          const r = msg.data;
          const resultsDiv = document.getElementById('results');
          document.getElementById('status-text').style.display = 'none';

          // 统计
          for (const t of r.tests) {
            if (t.status === 'passed') passedCount++;
            else if (t.status === 'failed') failedCount++;
            else errorCount++;
          }

          const levelBadge = r.overallVulnerable
            ? '<span class="badge badge-' + r.vulnerabilityLevel + '">' + r.vulnerabilityLevel.toUpperCase() + '</span>'
            : '';

          const testSummary = r.tests
            .filter(t => t.status === 'failed')
            .map(t => '<div class="finding">' + t.finding + '</div>')
            .join('');

          const card = document.createElement('div');
          card.className = 'result-card';
          card.innerHTML =
            '<div class="result-endpoint">' +
              r.endpoint.method + ' ' + r.endpoint.path +
              '<span class="host-tag">' + r.targetHost + '</span>' +
              levelBadge +
            '</div>' +
            '<div class="result-tests">' +
              r.tests.length + ' 项测试 | ' +
              r.tests.filter(t => t.status === 'passed').length + ' 通过 | ' +
              r.tests.filter(t => t.status === 'failed').length + ' 漏洞' +
            '</div>' +
            testSummary;

          resultsDiv.insertBefore(card, resultsDiv.firstChild);
          updateStats();
          break;
        }
        case 'complete': {
          document.getElementById('status-text').textContent =
            failedCount > 0
              ? '测试完成：发现 ' + failedCount + ' 个潜在漏洞！'
              : '测试完成：未发现漏洞';
          document.getElementById('status-text').style.display = 'block';
          break;
        }
        case 'log': {
          const logsDiv = document.getElementById('logs');
          logsDiv.style.display = 'block';
          const logContent = document.getElementById('log-content');
          logContent.innerHTML += msg.data + '<br>';
          break;
        }
      }
    });
  </script>
</body>
</html>`;
  }
}
