import * as vscode from 'vscode';
import { ScanContext, EndpointInfo, RiskLevel } from '../types';

/** 风险等级对应的图标 */
const RISK_ICONS: Record<RiskLevel, string> = {
  high: '$(error)',
  medium: '$(warning)',
  low: '$(info)',
  info: '$(circle-outline)'
};

/** 风险等级对应的 Tooltip */
const RISK_LABELS: Record<RiskLevel, string> = {
  high: '高危 - 可能存在越权/未授权访问',
  medium: '中危 - 涉及敏感数据',
  low: '低危 - 普通 API 接口',
  info: '信息 - 公开接口'
};

export class EndpointTreeProvider implements vscode.TreeDataProvider<EndpointTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<EndpointTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(private scanContext: ScanContext) {}

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: EndpointTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: EndpointTreeItem): EndpointTreeItem[] {
    if (element) {
      // 分组下的端点
      return element.children || [];
    }

    const ctx = this.scanContext;

    // 空闲状态 - 显示欢迎面板
    if (ctx.progress.phase === 'idle') {
      return this.buildWelcomeView();
    }

    // 扫描中
    if (ctx.progress.phase !== 'done') {
      return [new EndpointTreeItem(
        `${ctx.progress.message}（已发现 ${ctx.endpoints.length} 个端点）`,
        '$(sync~spin)',
        vscode.TreeItemCollapsibleState.None
      )];
    }

    // 无结果
    if (ctx.endpoints.length === 0) {
      return [new EndpointTreeItem(
        '未发现 API 端点',
        '$(circle-slash)',
        vscode.TreeItemCollapsibleState.None
      )];
    }

    // 按风险等级分组
    return this.buildGroupedTree(ctx.endpoints);
  }

  private buildGroupedTree(endpoints: EndpointInfo[]): EndpointTreeItem[] {
    const groups: Record<RiskLevel, EndpointInfo[]> = {
      high: [],
      medium: [],
      low: [],
      info: []
    };

    for (const ep of endpoints) {
      groups[ep.riskLevel].push(ep);
    }

    const items: EndpointTreeItem[] = [];
    const groupOrder: RiskLevel[] = ['high', 'medium', 'low', 'info'];

    for (const level of groupOrder) {
      const eps = groups[level];
      if (eps.length === 0) { continue; }

      const groupItem = new EndpointTreeItem(
        `${RISK_LABELS[level]} (${eps.length})`,
        RISK_ICONS[level],
        vscode.TreeItemCollapsibleState.Expanded
      );
      groupItem.contextValue = 'group';

      groupItem.children = eps.map(ep => {
        const methodIcon = this.getMethodIcon(ep.method);
        const label = `${methodIcon} ${ep.method} ${ep.path}`;
        const icon = ep.riskLevel === 'high' ? '$(error)' :
                     ep.riskLevel === 'medium' ? '$(warning)' : '$(circle-outline)';

        const item = new EndpointTreeItem(
          label,
          icon,
          vscode.TreeItemCollapsibleState.None
        );
        item.contextValue = 'endpoint';
        item.tooltip = this.buildTooltip(ep);
        item.command = {
          command: 'jsApiHunter.viewEndpointDetail',
          title: '查看详情',
          arguments: [ep]
        };

        // 保存端点引用（用于右键菜单等操作）
        item.endpoint = ep;
        return item;
      });

      items.push(groupItem);
    }

    return items;
  }

  private buildWelcomeView(): EndpointTreeItem[] {
    return [
      new EndpointTreeItem(
        '🚀 开始扫描',
        '$(search)',
        vscode.TreeItemCollapsibleState.None,
        undefined,
        { command: 'jsApiHunter.scan', title: '开始扫描' }
      ),
      new EndpointTreeItem(
        '📡 分析签名/加密逻辑',
        '$(key)',
        vscode.TreeItemCollapsibleState.None,
        undefined,
        { command: 'jsApiHunter.analyzeSignatures', title: '分析签名' }
      ),
      new EndpointTreeItem(
        '🔌 配置 AI 集成 (MCP)',
        '$(plug)',
        vscode.TreeItemCollapsibleState.None,
        undefined,
        { command: 'jsApiHunter.setupMcp', title: 'MCP 配置' }
      ),
      new EndpointTreeItem(
        '━━━━━━━━━━━━━━━━',
        '$(dash)',
        vscode.TreeItemCollapsibleState.None
      ),
      new EndpointTreeItem(
        '欢迎使用 JS API Hunter',
        '$(info)',
        vscode.TreeItemCollapsibleState.None
      ),
      new EndpointTreeItem(
        '输入 URL → 自动发现 API → 一键测试漏洞',
        '$(comment)',
        vscode.TreeItemCollapsibleState.None
      ),
    ];
  }

  private welcomeItem(label: string, icon: string, cmd?: string): EndpointTreeItem {
    return new EndpointTreeItem(
      label, icon, vscode.TreeItemCollapsibleState.None,
      undefined,
      cmd ? { command: cmd, title: label } : undefined
    );
  }

  private getMethodIcon(method: string): string {
    switch (method.toUpperCase()) {
      case 'GET': return '📥';
      case 'POST': return '📤';
      case 'PUT': return '📝';
      case 'DELETE': return '🗑️';
      case 'PATCH': return '🔧';
      default: return '❓';
    }
  }

  private buildTooltip(ep: EndpointInfo): string {
    let tip = `${ep.method} ${ep.path}`;
    if (ep.fullUrl) {
      tip += `\n完整URL: ${ep.fullUrl}`;
    }
    tip += `\n来源: ${ep.sourceFile}`;
    if (ep.tags.length > 0) {
      tip += `\n标签: ${ep.tags.join(', ')}`;
    }
    if (ep.parameters.length > 0) {
      tip += `\n参数: ${ep.parameters.length} 个`;
    }
    return tip;
  }
}

export class EndpointTreeItem extends vscode.TreeItem {
  children?: EndpointTreeItem[];
  endpoint?: EndpointInfo;

  constructor(
    label: string,
    icon: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    children?: EndpointTreeItem[],
    command?: vscode.Command
  ) {
    super(label, collapsibleState);
    this.iconPath = new vscode.ThemeIcon(icon.replace('$(', '').replace(')', '') as any)
      || undefined;
    this.children = children;
    if (command) {
      this.command = command;
    }
  }
}
