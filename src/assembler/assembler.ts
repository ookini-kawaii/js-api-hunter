import { EndpointInfo, JsFile } from '../types';

import * as vscode from 'vscode';

/**
 * 从 JS 文件中识别 baseURL 并拼装完整请求
 */
export function assembleRequests(endpoints: EndpointInfo[], jsFiles: JsFile[]): void {
  if (endpoints.length === 0) { return; }
  assembleBaseUrls(endpoints, jsFiles);
}

function assembleBaseUrls(endpoints: EndpointInfo[], jsFiles: JsFile[]): void {
  const baseUrls = extractBaseUrls(jsFiles);

  for (const ep of endpoints) {
    // 1. 尝试从来源文件匹配 baseURL
    const sourceFile = jsFiles.find(f => f.url === ep.sourceFile);
    if (sourceFile) {
      const fileBaseUrl = findBaseUrlInFile(sourceFile);
      if (fileBaseUrl) {
        ep.baseUrl = fileBaseUrl;
        ep.fullUrl = joinUrl(ep.baseUrl, ep.path);
        continue;
      }
    }

    // 2. 尝试从全局 baseURL 列表匹配
    const matchedBaseUrl = findBestBaseUrl(ep, baseUrls);
    if (matchedBaseUrl) {
      ep.baseUrl = matchedBaseUrl;
      ep.fullUrl = joinUrl(ep.baseUrl, ep.path);
      continue;
    }

    // 3. 兜底：path 本身可能就是完整的
    if (ep.path.startsWith('http://') || ep.path.startsWith('https://')) {
      ep.fullUrl = ep.path;
      try {
        const u = new URL(ep.path);
        ep.baseUrl = u.origin;
      } catch { /* ignore */ }
    } else {
      // 无法拼装的留空
      ep.fullUrl = ep.path;
    }
  }
}

/** 从所有 JS 文件中提取 baseURL */
function extractBaseUrls(jsFiles: JsFile[]): string[] {
  const baseUrls: string[] = [];

  for (const file of jsFiles) {
    const found = findBaseUrlInFile(file);
    if (found && !baseUrls.includes(found)) {
      baseUrls.push(found);
    }
  }

  return baseUrls;
}

/** 从单个 JS 文件中提取 baseURL */
function findBaseUrlInFile(file: JsFile): string | null {
  const content = file.content;

  // 匹配模式（按优先级）:
  const patterns = [
    // baseURL: 'https://api.example.com'
    /baseURL\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // BASE_URL: 'https://...'
    /BASE_URL\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // process.env.VUE_APP_API_URL / process.env.REACT_APP_API_URL
    /process\.env\.(?:VUE_APP|REACT_APP|NEXT_PUBLIC)_(?:API_)?(?:URL|BASE)\s*[:=]?\s*["'`]([^"'`]+)["'`]/gi,
    // VUE_APP_API_URL: 'https://...'
    /VUE_APP_(?:API_)?(?:URL|BASE)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // REACT_APP_API_URL
    /REACT_APP_(?:API_)?(?:URL|BASE)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // NEXT_PUBLIC_API_URL
    /NEXT_PUBLIC_API_(?:URL|BASE)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // API_URL / API_BASE
    /API_(?:URL|BASE|ENDPOINT)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // axios.create({ baseURL: 'https://...' })
    /axios\s*\.\s*create\s*\(\s*\{\s*baseURL\s*:\s*["'`]([^"'`]+)["'`]/gi,
    // this.baseUrl / this.apiUrl
    /this\.(?:baseUrl|apiUrl|apiBase)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // const apiBase = 'https://...'
    /(?:apiBase|apiUrl|apiHost|serverUrl)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // hostname / apiHost
    /(?:hostname|apiHost|serverHost)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
    // window.location.origin + '/api' 模式
    /origin\s*\+\s*["'`]([^"'`]+)["'`]/gi,
    // https://api. 开头的完整 URL
    /["'`](https?:\/\/(?:api|service|backend|gateway)\.[^"'`\s]+)["'`]/gi,
    // /v1  /v2  版本前缀
    /["'`](\/(?:api\/)?v\d+\/[^"'`\s]*)["'`]/gi
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match) {
      let url = match[1].trim();

      // 清理
      url = url.replace(/\/+$/, ''); // 去掉末尾斜杠

      // 如果是相对路径（如 /api），跳过
      if (url.startsWith('/') && !url.startsWith('//')) {
        continue;
      }

      // 确保有协议
      if (!url.startsWith('http')) {
        if (url.startsWith('//')) {
          url = 'https:' + url;
        } else {
          continue; // 不是有效 URL
        }
      }

      try {
        new URL(url);
        return url;
      } catch {
        continue;
      }
    }
  }

  return null;
}

/** 为端点找到最匹配的 baseURL */
function findBestBaseUrl(endpoint: EndpointInfo, baseUrls: string[]): string | null {
  if (baseUrls.length === 0) { return null; }
  if (baseUrls.length === 1) { return baseUrls[0]; }

  // 优先匹配路径中有相同版本号的
  const path = endpoint.path.toLowerCase();

  for (const base of baseUrls) {
    const baseLower = base.toLowerCase();

    // 版本号匹配
    const vMatch = path.match(/\/v(\d+)/);
    if (vMatch && baseLower.includes('/v' + vMatch[1])) {
      return base;
    }

    // 关键词匹配
    if (path.includes('/api/') && baseLower.includes('/api')) {
      return base;
    }
  }

  // 默认返回第一个
  return baseUrls[0];
}

/** 拼接 URL */
function joinUrl(base: string, path: string): string {
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }

  const baseTrimmed = base.replace(/\/+$/, '');
  const pathTrimmed = path.startsWith('/') ? path : '/' + path;

  return baseTrimmed + pathTrimmed;
}

/**
 * 重放验证：对每个拼装好的端点发送探测请求
 * 对应 PDF 第 5 章：先在 Burp Repeater 重放确认请求能通
 *
 * 注意：默认使用 GET 探测，POST/PUT/DELETE 等改为 HEAD 或 OPTIONS，
 *       避免触发副作用。返回端点的 isReachable / verifyStatus / verifyLength。
 *
 * 优化点：
 * - 并发控制，避免串行等待
 * - 可取消
 * - 进度回调
 * - 双重超时保护（AbortSignal + Promise.race），防止某些 Node 版本 fetch 挂死
 */
export interface VerifyOptions {
  token?: string;
  timeout?: number;
  concurrency?: number;
  onProgress?: (done: number, total: number) => void;
  cancellationToken?: vscode.CancellationToken;
}

export async function verifyEndpoints(
  endpoints: EndpointInfo[],
  options: VerifyOptions = {}
): Promise<void> {
  const {
    token,
    timeout = 5000,
    concurrency = 5,
    onProgress,
    cancellationToken
  } = options;

  const total = endpoints.length;
  let done = 0;
  let cancelled = false;

  // 取消时立刻设置标记并触发所有 AbortController
  const abortController = new AbortController();
  const disposables: vscode.Disposable[] = [];
  if (cancellationToken) {
    disposables.push(
      cancellationToken.onCancellationRequested(() => {
        cancelled = true;
        abortController.abort();
      })
    );
  }

  async function verifyOne(ep: EndpointInfo): Promise<void> {
    if (cancelled || abortController.signal.aborted) { return; }

    if (!ep.fullUrl || !ep.fullUrl.startsWith('http')) {
      ep.isReachable = false;
      ep.verifyStatus = 0;
      ep.verifyLength = 0;
      done++;
      onProgress?.(done, total);
      return;
    }

    const method = ep.method.toUpperCase();
    const probeMethod = method === 'GET' ? 'GET' : 'HEAD';
    const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
    if (token) { headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`; }

    // 每个请求独立的超时控制器
    const requestController = new AbortController();
    const timer = setTimeout(() => requestController.abort(), timeout);

    // 取消信号和超时信号合并
    const onAbort = () => requestController.abort();
    abortController.signal.addEventListener('abort', onAbort);

    try {
      const resp = await fetch(ep.fullUrl, {
        method: probeMethod,
        headers,
        signal: requestController.signal,
        redirect: 'manual'
      });

      clearTimeout(timer);

      // HEAD 请求通常没有 body，GET 请求读 body 用于长度统计
      const body = probeMethod === 'GET'
        ? await resp.text().catch(() => '')
        : '';

      ep.verifyStatus = resp.status;
      ep.verifyLength = body.length;
      ep.isReachable = resp.status > 0;
    } catch {
      ep.isReachable = false;
      ep.verifyStatus = 0;
      ep.verifyLength = 0;
    } finally {
      clearTimeout(timer);
      abortController.signal.removeEventListener('abort', onAbort);
      done++;
      onProgress?.(done, total);
    }
  }

  try {
    // 并发控制：每批 concurrency 个
    for (let i = 0; i < endpoints.length; i += concurrency) {
      if (cancelled || abortController.signal.aborted) { break; }
      const batch = endpoints.slice(i, i + concurrency);
      await Promise.all(batch.map(verifyOne));
    }
  } finally {
    disposables.forEach(d => d.dispose());
  }
}

/** 生成 cURL 命令 */
export function toCurl(endpoint: EndpointInfo, token?: string): string {
  const headers: Record<string, string> = { ...endpoint.headers };
  if (token) { headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`; }
  const headerStr = Object.entries(headers)
    .map(([k, v]) => `-H '${k}: ${v}'`)
    .join(' ');
  return `curl -X ${endpoint.method} ${headerStr} "${endpoint.fullUrl}"`;
}

/** 生成 Python requests 脚本 */
export function toPythonRequests(endpoint: EndpointInfo, token?: string): string {
  const headers: Record<string, string> = { ...endpoint.headers };
  if (token) { headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`; }
  const headerStr = JSON.stringify(headers, null, 2);
  return `import requests

url = "${endpoint.fullUrl}"
headers = ${headerStr}

resp = requests.${endpoint.method.toLowerCase()}(url, headers=headers, timeout=10)
print(resp.status_code)
print(resp.text[:500])
`;
}
