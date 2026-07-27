import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { EndpointInfo, EndpointCategory, JsFile, RiskLevel } from '../types';

/**
 * 端点过滤配置
 */
export interface FilterConfig {
  /** 是否启用智能过滤 */
  enabled: boolean;
  /** 保留的端点分类 */
  keepCategories: EndpointCategory[];
  /** 额外保留的路径关键词 */
  extraKeepKeywords: string[];
  /** 额外排除的路径关键词 */
  extraExcludeKeywords: string[];
}

/** 默认过滤配置：保留 API 类端点，排除静态资源和其他 */
export const DEFAULT_FILTER_CONFIG: FilterConfig = {
  enabled: true,
  keepCategories: ['api'],
  extraKeepKeywords: [],
  extraExcludeKeywords: []
};

/**
 * 从 JS 文件中解析 API 端点
 */
export function parseEndpoints(jsFiles: JsFile[]): EndpointInfo[] {
  const endpoints: EndpointInfo[] = [];
  const seen = new Set<string>();

  for (const file of jsFiles) {
    const extracted = extractFromFile(file);
    for (const ep of extracted) {
      const key = `${ep.method}:${ep.path}`;
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push(ep);
      }
    }
  }

  // 去重 + 排序
  return sortEndpoints(endpoints);
}

/**
 * 智能过滤端点：去重 + 排除静态资源 + 只保留 API 特征端点
 * 返回 { kept, filtered }，kept 是过滤后的端点列表
 */
export function filterEndpoints(
  endpoints: EndpointInfo[],
  config: FilterConfig = DEFAULT_FILTER_CONFIG
): { kept: EndpointInfo[]; filtered: EndpointInfo[] } {
  if (!config.enabled) {
    return { kept: endpoints, filtered: [] };
  }

  // 第一步：合并重复（同 method + path，保留第一个）
  const seen = new Map<string, EndpointInfo>();
  for (const ep of endpoints) {
    const key = `${ep.method.toUpperCase()}:${ep.path}`;
    if (!seen.has(key)) {
      seen.set(key, ep);
    }
  }
  const deduped = Array.from(seen.values());

  // 第二步：分类 + 过滤
  const kept: EndpointInfo[] = [];
  const filtered: EndpointInfo[] = [];

  for (const ep of deduped) {
    classifyEndpoint(ep, config);

    // 检查额外排除关键词
    if (config.extraExcludeKeywords.length > 0) {
      const shouldExclude = config.extraExcludeKeywords.some(kw =>
        ep.path.toLowerCase().includes(kw.toLowerCase())
      );
      if (shouldExclude) {
        ep.endpointCategory = 'static';
        filtered.push(ep);
        continue;
      }
    }

    // 检查额外保留关键词（即使分类是 static/other 也保留）
    if (config.extraKeepKeywords.length > 0) {
      const shouldKeep = config.extraKeepKeywords.some(kw =>
        ep.path.toLowerCase().includes(kw.toLowerCase())
      );
      if (shouldKeep) {
        ep.endpointCategory = 'api';
        kept.push(ep);
        continue;
      }
    }

    if (config.keepCategories.includes(ep.endpointCategory || 'api')) {
      kept.push(ep);
    } else {
      filtered.push(ep);
    }
  }

  return { kept: sortEndpoints(kept), filtered };
}

/**
 * 对端点进行分类：api / static / other
 */
function classifyEndpoint(ep: EndpointInfo, config: FilterConfig): void {
  const lower = ep.path.toLowerCase();

  // 静态资源明显特征
  const staticExtensions = [
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.webm', '.mp3', '.wav', '.ogg',
    '.pdf', '.zip', '.tar', '.gz', '.rar',
    '.map', '.json'
  ];
  if (staticExtensions.some(ext => lower.endsWith(ext))) {
    ep.endpointCategory = 'static';
    return;
  }

  // 打包产物：带 hash 的文件名
  if (/\/(chunk|bundle|vendor|runtime|polyfill|common)[-_\.]/.test(lower)) {
    ep.endpointCategory = 'other';
    return;
  }

  // 模块路径（无 API 特征）
  const nonApiPatterns = [
    /^\/node_modules\//,
    /^\/@/,
    /\/dist\//,
    /\/build\//,
    /\/public\//,
    /\/assets\//,
    /\/static\//,
    /\/vendor\//,
    /\/lib\//,
    /\/i18n\//,
    /\/locale\//,
    /\/lang\//,
    /\/theme\//,
    /\/style\//,
    /\/css\//,
    /\/img\//,
    /\/images\//,
    /\/icon\//,
    /\/font\//,
    /\/logo(\/|$|\.)/,
    /\/favicon(\/|$|\.)/,
    /\/manifest(\/|$|\.)/,
    /\/robots(\/|$|\.)/,
    /\/sitemap(\/|$|\.)/,
  ];
  if (nonApiPatterns.some(p => p.test(lower))) {
    ep.endpointCategory = 'static';
    return;
  }

  // API 特征关键词
  const apiKeywords = [
    '/api', '/v1/', '/v2/', '/v3/', '/v4/', '/v5/',
    '/rest/', '/graphql', '/ajax', '/rpc',
    '/login', '/logout', '/register', '/signup', '/signin',
    '/user', '/users', '/profile', '/account',
    '/admin', '/manage', '/dashboard',
    '/order', '/pay', '/cart', '/checkout',
    '/search', '/query', '/list',
    '/upload', '/download', '/export',
    '/config', '/setting', '/settings',
    '/auth', '/token', '/session', '/oauth',
    '/webhook', '/callback', '/notify',
    '/health', '/status', '/ping',
    '/cron', '/job', '/task',
    '/message', '/chat', '/comment',
    '/file', '/image', '/media',
    '/data', '/stats', '/analytics',
    '/metric', '/log',
  ];
  if (apiKeywords.some(kw => lower.includes(kw))) {
    ep.endpointCategory = 'api';
    return;
  }

  // 路径看起来像 API 路径（深层路径、含参数等）
  const pathSegments = ep.path.split('/').filter(Boolean);
  // 单段路径且不是 api 相关 -> 可能是静态路由
  if (pathSegments.length <= 1) {
    ep.endpointCategory = 'other';
    return;
  }

  // 默认归类为 other
  ep.endpointCategory = 'other';
}

function extractFromFile(file: JsFile): EndpointInfo[] {
  const endpoints: EndpointInfo[] = [];
  const content = file.content;

  // === 策略1: 正则提取 - 覆盖率最高 ===
  endpoints.push(...regexExtractEndpoints(content, file));

  // === 策略2: AST 解析 - 更精确 ===
  try {
    endpoints.push(...astExtractEndpoints(content, file));
  } catch {
    // AST 解析失败（minified code 等），使用正则结果即可
  }

  return endpoints;
}

/** 正则提取 API 端点 */
function regexExtractEndpoints(content: string, file: JsFile): EndpointInfo[] {
  const results: EndpointInfo[] = [];

  // 匹配各种 HTTP 请求模式
  const patterns = [
    // fetch('/api/users')
    /fetch\s*\(\s*["'`]([^"'`]+)["'`]/g,
    // axios.get('/api/users')
    /(?:axios|http|request|api)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    // $.ajax({ url: '/api/users' })
    /\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]/gi,
    // url: '/api/users'
    /url\s*:\s*["'`]([^"'`]+)["'`]/gi,
    // XMLHttpRequest open
    /\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi,
    // 直接的 API 路径模式
    /["'`](\/(?:api|v\d|rest|graphql|admin|user|auth|login|config|health)\/[^"'`\s]+)["'`]/gi,
    // router.get/post/put/delete
    /\.(?:get|post|put|delete|patch|all|use)\s*\(\s*["'`]([^"'`]+)["'`]/gi
  ];

  const seenPaths = new Set<string>();

  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    pattern.lastIndex = 0;

    while ((match = pattern.exec(content)) !== null) {
      let path: string;
      let method = 'GET';

      // XMLHttpRequest 模式有两个捕获组
      if (match.length >= 3) {
        method = match[1].toUpperCase();
        path = match[2];
      } else {
        path = match[1];
      }

      // 过滤误报
      if (!isValidPath(path)) { continue; }
      if (seenPaths.has(path)) { continue; }
      seenPaths.add(path);

      // 推断 method
      method = inferMethod(path, content, match.index) || method;

      results.push(createEndpoint(path, method, file));
    }
  }

  return results;
}

/** AST 解析提取端点 */
function astExtractEndpoints(content: string, file: JsFile): EndpointInfo[] {
  const results: EndpointInfo[] = [];
  const ast = acorn.parse(content, {
    ecmaVersion: 'latest',
    sourceType: 'module',
    locations: true
  });
  const seenPaths = new Set<string>();

  walk.simple(ast, {
    CallExpression(node: any) {
      // 处理 url + method 形式的调用
      if (
        node.arguments?.length >= 1 &&
        node.arguments[0].type === 'Literal' &&
        typeof node.arguments[0].value === 'string'
      ) {
        const path = node.arguments[0].value;
        if (isValidPath(path) && !seenPaths.has(path)) {
          seenPaths.add(path);
          results.push(createEndpoint(path, 'GET', file));
        }
      }
    }
  });

  return results;
}

/** 创建端点对象 */
function createEndpoint(path: string, method: string, file: JsFile): EndpointInfo {
  const risk = assessRisk(path, method, file.content);
  const tags = generateTags(path, method, file.content);

  return {
    id: `${method}_${path}_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    url: '',
    method,
    path,
    baseUrl: '',
    fullUrl: '', // 稍后由 assembler 填充
    headers: {},
    parameters: [],
    sourceFile: file.url,
    riskLevel: risk,
    tags
  };
}

/** 判断是否是有效 API 路径 */
function isValidPath(path: string): boolean {
  if (!path || path.length < 2) { return false; }

  // 过滤明显不是 API 路径的
  const skipPatterns = [
    /^https?:\/\//,           // 完整 URL（外部链接）
    /^\/\//,                   // 协议相对 URL
    /^data:/,                  // data URI
    /^blob:/,                  // blob URI
    /^#/,                      // 锚点
    /\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i,  // 静态资源
    /^javascript:/             // javascript: URI
  ];

  return !skipPatterns.some(p => p.test(path));
}

/** 推断 HTTP Method */
function inferMethod(path: string, content: string, index: number): string | null {
  const context = content.substring(Math.max(0, index - 50), index);
  const ctxLower = context.toLowerCase();

  if (ctxLower.includes('.post(') || ctxLower.includes('"post"') || ctxLower.includes("'post'")) { return 'POST'; }
  if (ctxLower.includes('.put(') || ctxLower.includes('"put"') || ctxLower.includes("'put'")) { return 'PUT'; }
  if (ctxLower.includes('.delete(') || ctxLower.includes('"delete"') || ctxLower.includes("'delete'")) { return 'DELETE'; }
  if (ctxLower.includes('.patch(') || ctxLower.includes('"patch"') || ctxLower.includes("'patch'")) { return 'PATCH'; }

  // 路径名推断
  const lower = path.toLowerCase();
  if (lower.includes('delete') || lower.includes('remove')) { return 'DELETE'; }
  if (lower.includes('create') || lower.includes('add') || lower.includes('save') || lower.includes('upload')) { return 'POST'; }
  if (lower.includes('update') || lower.includes('edit')) { return 'PUT'; }

  return null;
}

/** 评估风险等级 */
function assessRisk(path: string, method: string, content: string): RiskLevel {
  const lower = path.toLowerCase();

  // 高危：管理接口
  if (
    lower.includes('/admin') ||
    lower.includes('/manage') ||
    lower.includes('/config') ||
    lower.includes('/debug') ||
    lower.includes('/backup') ||
    lower.includes('/internal')
  ) {
    return 'high';
  }

  // 高危：危险 method + 敏感路径
  if (
    (method === 'DELETE' || method === 'PUT') &&
    (lower.includes('/user') || lower.includes('/order') || lower.includes('/account'))
  ) {
    return 'high';
  }

  // 中危：涉及用户数据
  if (
    lower.includes('/user') ||
    lower.includes('/profile') ||
    lower.includes('/order') ||
    lower.includes('/payment') ||
    lower.includes('/secret') ||
    lower.includes('/private')
  ) {
    return 'medium';
  }

  // 低危：API 接口
  if (lower.startsWith('/api') || lower.startsWith('/v')) {
    return 'low';
  }

  return 'info';
}

/** 生成标签 */
function generateTags(path: string, method: string, content: string): string[] {
  const tags: string[] = [];
  const lower = path.toLowerCase();

  if (lower.includes('/admin') || lower.includes('/manage')) { tags.push('admin'); }
  if (lower.includes('/api')) { tags.push('api'); }
  if (lower.includes('/auth') || lower.includes('/login') || lower.includes('/token')) { tags.push('auth'); }
  if (lower.includes('/user')) { tags.push('user'); }
  if (lower.includes('/config') || lower.includes('/setting')) { tags.push('config'); }
  if (lower.includes('/upload') || lower.includes('/file')) { tags.push('file'); }
  if (lower.includes('/graphql')) { tags.push('graphql'); }
  if (method === 'DELETE') { tags.push('destructive'); }

  return tags;
}

/** 排序：高风险在前 */
function sortEndpoints(endpoints: EndpointInfo[]): EndpointInfo[] {
  const riskOrder: Record<RiskLevel, number> = { high: 0, medium: 1, low: 2, info: 3 };
  return endpoints.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);
}
