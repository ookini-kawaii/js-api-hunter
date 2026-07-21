import * as vscode from 'vscode';
import { EndpointTreeProvider } from './tree/endpointTree';
import { registerCommands } from './commands';
import { ScanContext } from './types';

export function activate(context: vscode.ExtensionContext) {
  // 全局扫描上下文
  const scanContext: ScanContext = {
    targetUrl: '',
    jsFiles: [],
    endpoints: [],
    fuzzResults: [],
    progress: { phase: 'idle', jsFilesFound: 0, endpointsFound: 0, message: '就绪' }
  };

  // 注册 TreeView
  const treeProvider = new EndpointTreeProvider(scanContext);
  const treeView = vscode.window.createTreeView('js-api-hunter-endpoints', {
    treeDataProvider: treeProvider,
    showCollapseAll: true
  });

  // 注册命令
  registerCommands(context, scanContext, treeProvider);

  // 状态栏
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'jsApiHunter.scan';
  statusBar.text = '$(bug) JS API Hunter';
  statusBar.tooltip = '点击开始扫描';
  statusBar.show();

  context.subscriptions.push(treeView, statusBar);
}

export function deactivate() {
  // 清理资源
}
