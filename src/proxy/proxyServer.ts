/**
 * 被动代理服务器
 * 监听本地端口，捕获浏览器 HTTP 请求，自动收集 JS 文件
 *
 * 用法：启动代理 → 浏览器设置代理 localhost:8080 → 浏览目标网站 → 自动收集 JS
 */

import * as http from 'http';
import * as net from 'net';
import * as url from 'url';
import { JsFile } from '../types';

export interface ProxyInfo {
  port: number;
  jsCount: number;
}

let currentServer: http.Server | null = null;
let currentPort: number = 0;
let onJsCollected: ((file: JsFile) => void) | null = null;

/**
 * 启动被动代理服务器
 */
export function startProxyServer(
  port: number,
  onCollect: (file: JsFile) => void
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (currentServer) {
      reject(new Error('代理已在运行中，请先停止'));
      return;
    }

    onJsCollected = onCollect;
    currentPort = port;

    currentServer = http.createServer((clientReq, clientRes) => {
      // HTTP 转发
      handleHttp(clientReq, clientRes);
    });

    // HTTPS CONNECT 隧道：需要监听 'connect' 事件获取原始 Socket
    currentServer.on('connect', (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
      const [hostname, portStr] = (req.url || '').split(':');
      const targetPort = parseInt(portStr) || 443;
      handleConnect(req, clientSocket, head, hostname, targetPort);
    });

    currentServer.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        reject(new Error(`端口 ${port} 已被占用，请选择其他端口`));
      } else {
        reject(err);
      }
    });

    currentServer.listen(port, '127.0.0.1', () => {
      resolve();
    });
  });
}

/**
 * 停止代理服务器
 */
export function stopProxyServer(): void {
  if (currentServer) {
    currentServer.close();
    currentServer = null;
    currentPort = 0;
    onJsCollected = null;
  }
}

/**
 * 获取当前代理状态
 */
export function getProxyServer(): ProxyInfo | null {
  if (!currentServer) { return null; }
  return {
    port: currentPort,
    jsCount: 0  // 由 commands.ts 管理
  };
}

/** 处理 HTTPS CONNECT 隧道 */
function handleConnect(
  clientReq: http.IncomingMessage,
  clientSocket: net.Socket,
  head: Buffer,
  hostname: string,
  port: number
): void {
  const serverSocket = net.connect(port, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) {
      serverSocket.write(head);
    }
    // 双向管道
    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  });

  serverSocket.on('error', () => {
    clientSocket.end();
  });

  clientSocket.on('error', () => {
    serverSocket.end();
  });

  clientReq.on('error', () => {});
}

/** 处理 HTTP 转发并收集 JS */
function handleHttp(
  clientReq: http.IncomingMessage,
  clientRes: http.ServerResponse
): void {
  const targetUrl = clientReq.url || '';
  if (!targetUrl || targetUrl.startsWith('//')) {
    clientRes.writeHead(400);
    clientRes.end();
    return;
  }

  const options = url.parse(targetUrl);
  const isHttps = options.protocol === 'https:';
  const transport = isHttps ? require('https') : http;
  const port = options.port || (isHttps ? 443 : 80);

  const proxyReq = transport.request({
    hostname: options.hostname,
    port: port,
    path: options.path,
    method: clientReq.method,
    headers: { ...clientReq.headers },
  }, (proxyRes: http.IncomingMessage) => {
    const chunks: Buffer[] = [];
    const isJs = isJavaScriptResponse(proxyRes, targetUrl);

    if (isJs) {
      proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
    }

    proxyRes.on('end', () => {
      // 收集 JS 文件
      if (isJs && onJsCollected && chunks.length > 0) {
        const content = Buffer.concat(chunks).toString('utf-8');
        if (content.trim().length > 50) {
          onJsCollected({
            url: targetUrl,
            content,
            source: 'puppeteer',
            size: content.length
          });
        }
      }

      if (!clientRes.headersSent) {
        clientRes.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        if (chunks.length > 0) {
          clientRes.end(Buffer.concat(chunks));
        } else {
          clientRes.end();
        }
      }
    });

    // 非 JS 直接转发
    if (!isJs) {
      proxyRes.pipe(clientRes);
    }
  });

  proxyReq.on('error', () => {
    if (!clientRes.headersSent) {
      clientRes.writeHead(502);
      clientRes.end();
    }
  });

  clientReq.pipe(proxyReq);
}

/** 判断响应是否为 JS 文件 */
function isJavaScriptResponse(
  proxyRes: http.IncomingMessage,
  requestUrl: string
): boolean {
  const contentType = (proxyRes.headers['content-type'] || '').toLowerCase();
  const urlLower = requestUrl.toLowerCase();

  // 通过 Content-Type
  if (
    contentType.includes('javascript') ||
    contentType.includes('text/js') ||
    contentType.includes('application/js')
  ) {
    return true;
  }

  // 通过 URL（很多 JS 文件没有正确的 Content-Type）
  if (
    urlLower.endsWith('.js') ||
    urlLower.includes('.js?') ||
    urlLower.includes('.js#')
  ) {
    return true;
  }

  return false;
}
