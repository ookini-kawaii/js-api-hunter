import * as vscode from 'vscode';
import { ScanContext, EndpointInfo, RiskLevel, SecretFinding, SubdomainInfo } from '../types';

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

/** TreeView 顶层分类 */
type CategoryType = 'endpoints' | 'secrets' | 'subdomains';

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
      if (element.children) { return element.children; }
      return [];
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

    // 完成后：按分类展示
    return this.buildCategoryTree();
  }

  private buildCategoryTree(): EndpointTreeItem[] {
    const ctx = this.scanContext;
    const items: EndpointTreeItem[] = [];

    // 端点分类
    const endpointCategory = new EndpointTreeItem(
      `API 端点 (${ctx.endpoints.length})`,
      '$(list-unordered)',
      vscode.TreeItemCollapsibleState.Expanded,
      this.buildGroupedTree(ctx.endpoints)
    );
    endpointCategory.contextValue = 'category';
    items.push(endpointCategory);

    // 敏感信息分类
    const secretCategory = new EndpointTreeItem(
      `敏感信息 (${ctx.secrets.length})`,
      '$(key)',
      ctx.secrets.length > 0 ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None,
      this.buildSecretTree(ctx.secrets)
    );
    secretCategory.contextValue = 'category';
    secretCategory.command = ctx.secrets.length > 0
      ? { command: 'jsApiHunter.showSecrets', title: '查看敏感信息' }
      : undefined;
    items.push(secretCategory);

    // 子域名分类
    const aliveCount = ctx.subdomains.filter(s => s.isAlive).length;
    const subdomainCategory = new EndpointTreeItem(
      `子域名 (${aliveCount}/${ctx.subdomains.length})`,
      '$(globe)',
      ctx.subdomains.length > 0 ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None,
      this.buildSubdomainTree(ctx.subdomains)
    );
    subdomainCategory.contextValue = 'category';
    items.push(subdomainCategory);

    return items;
  }

  private buildGroupedTree(endpoints: EndpointInfo[]): EndpointTreeItem[] {
    if (endpoints.length === 0) {
      return [new EndpointTreeItem('未发现 API 端点', '$(circle-slash)', vscode.TreeItemCollapsibleState.None)];
    }

    const groups: Record<RiskLevel, EndpointInfo[]> = { high: [], medium: [], low: [], info: [] };
    for (const ep of endpoints) { groups[ep.riskLevel].push(ep); }

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
        const icon = ep.isReachable === false ? '$(debug-disconnect)'
          : ep.riskLevel === 'high' ? '$(error)'
            : ep.riskLevel === 'medium' ? '$(warning)' : '$(circle-outline)';

        const item = new EndpointTreeItem(label, icon, vscode.TreeItemCollapsibleState.None);
        item.contextValue = 'endpoint';
        item.tooltip = this.buildTooltip(ep);
        item.command = {
          command: 'jsApiHunter.viewEndpointDetail',
          title: '查看详情',
          arguments: [ep]
        };
        item.endpoint = ep;
        return item;
      });

      items.push(groupItem);
    }

    return items;
  }

  private buildSecretTree(secrets: SecretFinding[]): EndpointTreeItem[] {
    if (secrets.length === 0) {
      return [new EndpointTreeItem('未发现敏感信息', '$(circle-slash)', vscode.TreeItemCollapsibleState.None)];
    }

    return secrets.slice(0, 50).map(s => {
      const item = new EndpointTreeItem(
        `${s.type}: ${s.name}`,
        s.riskLevel === 'high' ? '$(error)' : '$(warning)',
        vscode.TreeItemCollapsibleState.None
      );
      item.tooltip = `值: ${s.value}\n来源: ${s.sourceFile}`;
      return item;
    });
  }

  private buildSubdomainTree(subdomains: SubdomainInfo[]): EndpointTreeItem[] {
    if (subdomains.length === 0) {
      return [new EndpointTreeItem('未收集子域名', '$(circle-slash)', vscode.TreeItemCollapsibleState.None)];
    }

    // 按分类分组
    const groups: Record<string, SubdomainInfo[]> = {};
    for (const s of subdomains) {
      const cat = s.category || 'other';
      if (!groups[cat]) { groups[cat] = []; }
      groups[cat].push(s);
    }

    const categoryLabels: Record<string, string> = {
      test: '测试环境（高价值）',
      legacy: '老系统（高价值）',
      admin: '管理后台',
      api: 'API / 微服务',
      internal: '内部域名',
      other: '其他'
    };

    const items: EndpointTreeItem[] = [];
    for (const [cat, hosts] of Object.entries(groups)) {
      const aliveCount = hosts.filter(h => h.isAlive).length;
      const groupItem = new EndpointTreeItem(
        `${categoryLabels[cat] || cat} (${aliveCount}/${hosts.length})`,
        '$(folder)',
        vscode.TreeItemCollapsibleState.Collapsed
      );
      groupItem.contextValue = 'subdomain-group';
      groupItem.children = hosts
        .sort((a, b) => (a.isAlive === b.isAlive ? 0 : a.isAlive ? -1 : 1))
        .map(s => {
          const item = new EndpointTreeItem(
            `${s.isAlive ? '✓' : '✗'} ${s.host}`,
            s.isAlive ? '$(globe)' : '$(debug-disconnect)',
            vscode.TreeItemCollapsibleState.None
          );
          item.tooltip = `分类: ${categoryLabels[s.category || 'other'] || s.category}\n来源: ${s.source || '-'}\nIP: ${s.ip || '-'}\nHTTP: ${s.httpStatus || '-'}\n${s.note || ''}`;
          return item;
        });
      items.push(groupItem);
    }

    return items;
  }

  private buildWelcomeView(): EndpointTreeItem[] {
    return [
      this.welcomeItem('开始扫描', '$(search)', 'jsApiHunter.scan'),
      this.welcomeItem('子域名枚举', '$(globe)', 'jsApiHunter.enumerateSubdomains'),
      this.welcomeItem('分析签名/加密逻辑', '$(key)', 'jsApiHunter.analyzeSignatures'),
      this.welcomeItem('配置 AI 集成 (MCP)', '$(plug)', 'jsApiHunter.setupMcp'),
      new EndpointTreeItem('━━━━━━━━━━━━━━━━', '$(dash)', vscode.TreeItemCollapsibleState.None),
      new EndpointTreeItem('欢迎使用 JS API Hunter', '$(info)', vscode.TreeItemCollapsibleState.None),
      new EndpointTreeItem('输入 URL → 自动发现 API → 一键测试漏洞', '$(comment)', vscode.TreeItemCollapsibleState.None),
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
    if (ep.fullUrl) { tip += `\n完整URL: ${ep.fullUrl}`; }
    if (ep.baseUrl) { tip += `\nbaseURL: ${ep.baseUrl}`; }
    tip += `\n来源: ${ep.sourceFile}`;
    if (ep.tags.length > 0) { tip += `\n标签: ${ep.tags.join(', ')}`; }
    if (ep.isReachable !== undefined) {
      tip += `\n验证: ${ep.isReachable ? '可达' : '不可达'} (${ep.verifyStatus || '-'})`;
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
    this.iconPath = new vscode.ThemeIcon(icon.replace('$(', '').replace(')', '') as any) || undefined;
    this.children = children;
    if (command) {
      this.command = command;
    }
  }
}
