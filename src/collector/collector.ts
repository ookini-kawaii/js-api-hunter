import * as puppeteer from 'puppeteer-core';
import { JsFile, JsSource } from '../types';

/**
 * 收集目标网站的所有 JS 文件
 * - 使用 Puppeteer 打开网站，拦截网络请求
 * - 可选：从 Wayback Machine 等被动来源补充
 */
export async function collectJsFiles(
  targetUrl: string,
  onProgress?: (count: number) => void
): Promise<JsFile[]> {
  const jsFiles: JsFile[] = [];
  const collectedUrls = new Set<string>();

  // 查找本地 Chrome/Chromium
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
    executablePath: findChromePath()
  });

  try {
    const page = await browser.newPage();
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );

    // 拦截所有网络响应，收集 .js 文件
    page.on('response', async (response) => {
      const url = response.url();
      const contentType = response.headers()['content-type'] || '';

      if (collectedUrls.has(url)) { return; }

      // 判断是否是 JS 文件
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

          if (onProgress) {
            onProgress(jsFiles.length);
          }
        }
      } catch {
        // 跳过无法读取的文件
      }
    });

    // 访问目标网站
    await page.goto(targetUrl, {
      waitUntil: 'networkidle2',
      timeout: 30000
    });

    // 等待一下确保所有异步加载的 JS 都被捕获
    await new Promise(resolve => setTimeout(resolve, 3000));

  } finally {
    await browser.close();
  }

  return jsFiles;
}

/** 查找系统中的 Chrome/Chromium 路径 */
function findChromePath(): string {
  if (process.platform === 'win32') {
    const paths = [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files\\Chromium\\Application\\chrome.exe'
    ];
    for (const p of paths) {
      try {
        require('fs').accessSync(p);
        return p;
      } catch { /* 不存在，继续 */ }
    }
  } else if (process.platform === 'darwin') {
    return '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  } else {
    return '/usr/bin/google-chrome';
  }
  return 'chrome'; // 兜底：尝试系统 PATH 中的 chrome
}
