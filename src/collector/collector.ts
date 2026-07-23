import { JsFile, JsSource } from '../types';
import { discoverSourceMaps } from './sourcemap';

/**
 * 收集目标网站的所有 JS 文件
 * 策略：先尝试纯 HTTP 抓取，再尝试 Puppeteer 兜底，最后自动发现 Source Map
 */
export async function collectJsFiles(
  targetUrl: string,
  onProgress?: (count: number) => void
): Promise<JsFile[]> {
  const jsFiles: JsFile[] = [];
  const collectedUrls = new Set<string>();

  // 先尝试纯 HTTP 方式（更可靠，不受沙箱限制）
  try {
    await collectViaHttp(targetUrl, jsFiles, collectedUrls, onProgress);
  } catch (err: any) {
    console.log('HTTP 收集失败，尝试 Puppeteer: ' + err.message);
  }

  // 如果 HTTP 没收集到东西，尝试 Puppeteer
  if (jsFiles.length === 0) {
    try {
      await collectViaPuppeteer(targetUrl, jsFiles, collectedUrls, onProgress);
    } catch (err: any) {
      throw new Error(`JS 收集失败: ${err.message}。请检查 URL 是否正确、网络是否可达。`);
    }
  }

  // 自动发现 Source Map 并还原源码
  try {
    const restored = await discoverSourceMaps(jsFiles, (count) => {
      if (onProgress) { onProgress(jsFiles.length + count); }
    });
    for (const f of restored) {
      if (!collectedUrls.has(f.url)) {
        collectedUrls.add(f.url);
        jsFiles.push(f);
      }
    }
  } catch {
    // Source Map 发现失败不影响主流程
  }

  return jsFiles;
}

/** 纯 HTTP 方式收集 JS 文件 */
async function collectViaHttp(
  targetUrl: string,
  jsFiles: JsFile[],
  collectedUrls: Set<string>,
  onProgress?: (count: number) => void
): Promise<void> {
  // 1. 抓取 HTML
  const htmlResp = await fetch(targetUrl, {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
  });

  if (!htmlResp.ok) {
    throw new Error(`HTTP ${htmlResp.status}: 页面返回错误`);
  }

  const html = await htmlResp.text();
  const baseUrl = new URL(targetUrl);

  // 2. 从 HTML 中提取 <script> 标签
  const scriptUrls = extractScriptUrls(html, baseUrl);

  if (onProgress) {
    onProgress(0);
  }

  // 3. 并发下载所有 JS 文件
  const results = await Promise.allSettled(
    scriptUrls.map(async (url) => {
      if (collectedUrls.has(url)) { return; }

      try {
        const resp = await fetch(url, {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(15000)
        });

        if (resp.ok) {
          const content = await resp.text();
          if (content && content.length > 10) {
            collectedUrls.add(url);
            jsFiles.push({
              url,
              content,
              source: 'manual' as JsSource,
              size: content.length
            });

            if (onProgress) {
              onProgress(jsFiles.length);
            }
          }
        }
      } catch {
        // 跳过无法下载的文件
      }
    })
  );

  // 4. 也把 HTML 本身当做一个源来解析（内联脚本）
  const inlineScripts = extractInlineScripts(html);
  if (inlineScripts.length > 0) {
    collectedUrls.add(targetUrl + '#inline');
    jsFiles.push({
      url: targetUrl + '#inline',
      content: inlineScripts.join('\n'),
      source: 'manual' as JsSource,
      size: inlineScripts.join('\n').length
    });
  }
}

/** 从 HTML 中提取 <script src="..."> 的 URL */
function extractScriptUrls(html: string, baseUrl: URL): string[] {
  const urls: string[] = [];
  const regex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(html)) !== null) {
    let url = match[1];
    // 转绝对路径
    if (url.startsWith('//')) {
      url = baseUrl.protocol + url;
    } else if (url.startsWith('/')) {
      url = baseUrl.origin + url;
    } else if (!url.startsWith('http')) {
      url = baseUrl.origin + '/' + url;
    }
    urls.push(url);
  }

  return [...new Set(urls)];
}

/** 提取内联 <script> 标签的内容 */
function extractInlineScripts(html: string): string[] {
  const scripts: string[] = [];
  const regex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(html)) !== null) {
    const content = match[1].trim();
    if (content.length > 10) {
      scripts.push(content);
    }
  }

  return scripts;
}

/** Puppeteer 方式收集 JS（兜底） */
async function collectViaPuppeteer(
  targetUrl: string,
  jsFiles: JsFile[],
  collectedUrls: Set<string>,
  onProgress?: (count: number) => void
): Promise<void> {
  // 动态导入，避免强制要求 Puppeteer 启动
  const puppeteer = await import('puppeteer-core');

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    executablePath: findChromePath()
  });

  try {
    const page = await browser.newPage();
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
    );

    page.on('response', async (response) => {
      const url = response.url();
      const contentType = response.headers()['content-type'] || '';

      if (collectedUrls.has(url)) { return; }

      const isJsFile =
        url.endsWith('.js') ||
        contentType.includes('javascript') ||
        contentType.includes('ecmascript') ||
        url.includes('.js?') ||
        url.includes('.bundle.');

      if (!isJsFile) { return; }

      try {
        const text = await response.text();
        if (text && text.length > 0) {
          collectedUrls.add(url);
          jsFiles.push({
            url,
            content: text,
            source: 'puppeteer' as JsSource,
            size: text.length
          });

          if (onProgress) { onProgress(jsFiles.length); }
        }
      } catch { /* skip */ }
    });

    await page.goto(targetUrl, {
      waitUntil: 'networkidle2',
      timeout: 30000
    });

    await new Promise(resolve => setTimeout(resolve, 3000));
  } finally {
    await browser.close();
  }
}

function findChromePath(): string {
  if (process.platform === 'win32') {
    const paths = [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      (process.env.LOCALAPPDATA || '') + '\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files\\Chromium\\Application\\chrome.exe'
    ];
    for (const p of paths) {
      try { require('fs').accessSync(p); return p; } catch { /* continue */ }
    }
  } else if (process.platform === 'darwin') {
    return '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  } else {
    return '/usr/bin/google-chrome';
  }
  return 'chrome';
}
