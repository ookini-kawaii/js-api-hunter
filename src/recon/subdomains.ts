/**
 * 子域名枚举
 * 对应 PDF 第 7 章：收集目标的所有子域名
 * 支持：前缀爆破、crt.sh 证书透明度、HTTP 存活探测
 */

import * as dns from 'dns';
import { SubdomainCategory, SubdomainInfo } from '../types';

/** 默认高价值子域名前缀（按 PDF 出洞率排序） */
export const DEFAULT_SUBDOMAIN_PREFIXES = [
  'test', 'dev', 'staging', 'uat', 'qa',
  'old', 'legacy', 'internal',
  'admin', 'manage', 'manager',
  'api', 'app', 'mobile', 'wap',
  'beta', 'alpha', 'demo', 'sandbox', 'preprod', 'pre', 'stage',
  'cms', 'portal', 'console', 'dashboard',
  'user-svc', 'order-svc', 'pay-svc', 'gateway', 'gw',
  'test-api', 'dev-api', 'staging-api'
];

/** 子域名前缀 → 分类映射 */
const CATEGORY_MAP: Record<string, SubdomainCategory> = {
  test: 'test', dev: 'test', staging: 'test', uat: 'test', qa: 'test',
  beta: 'test', alpha: 'test', demo: 'test', sandbox: 'test', preprod: 'test', pre: 'test', stage: 'test',
  old: 'legacy', legacy: 'legacy',
  internal: 'internal',
  admin: 'admin', manage: 'admin', manager: 'admin', cms: 'admin', portal: 'admin', console: 'admin', dashboard: 'admin',
  api: 'api', app: 'api', mobile: 'api', wap: 'api',
  'user-svc': 'api', 'order-svc': 'api', 'pay-svc': 'api', gateway: 'api', gw: 'api',
  'test-api': 'test', 'dev-api': 'test', 'staging-api': 'test'
};

/**
 * 子域名枚举（DNS 解析 + HTTP 探测 + crt.sh）
 */
export async function enumerateSubdomains(
  rootDomain: string,
  prefixes: string[] = DEFAULT_SUBDOMAIN_PREFIXES,
  onProgress?: (host: string, info: SubdomainInfo) => void
): Promise<SubdomainInfo[]> {
  const map = new Map<string, SubdomainInfo>();

  // 1. 前缀爆破
  const batchSize = 10;
  for (let i = 0; i < prefixes.length; i += batchSize) {
    const batch = prefixes.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(prefix => probeSubdomain(prefix, rootDomain, 'prefix', onProgress))
    );
    for (const info of batchResults) {
      map.set(info.host, info);
    }
  }

  // 2. crt.sh 证书透明度补充
  try {
    const crtshHosts = await fetchCrtshSubdomains(rootDomain);
    for (const host of crtshHosts) {
      if (map.has(host)) { continue; }
      const info = await probeExistingHost(host, 'crtsh');
      map.set(info.host, info);
      if (onProgress) { onProgress(info.host, info); }
    }
  } catch {
    // crt.sh 失败不影响主流程
  }

  return Array.from(map.values());
}

async function probeSubdomain(
  prefix: string,
  rootDomain: string,
  source: string,
  onProgress?: (host: string, info: SubdomainInfo) => void
): Promise<SubdomainInfo> {
  const host = `${prefix}.${rootDomain}`;
  const info = await probeExistingHost(host, source);
  if (onProgress) { onProgress(host, info); }
  return info;
}

async function probeExistingHost(host: string, source: string): Promise<SubdomainInfo> {
  const prefix = host.split('.')[0];
  const category = CATEGORY_MAP[prefix] || 'other';
  const info: SubdomainInfo = { host, isAlive: false, category, source };

  // 1. DNS 解析
  try {
    const addresses = await dns.promises.resolve4(host);
    if (addresses.length > 0) {
      info.ip = addresses[0];
      info.isAlive = true;
    }
  } catch {
    info.note = 'DNS 解析失败';
  }

  // 2. HTTP 探测（PDF 推荐只保留 200/302/401/403）
  for (const protocol of ['https', 'http']) {
    try {
      const resp = await fetch(`${protocol}://${host}/`, {
        method: 'HEAD',
        headers: { 'User-Agent': 'Mozilla/5.0' },
        signal: AbortSignal.timeout(8000),
        redirect: 'manual'
      });
      info.httpStatus = resp.status;
      if ([200, 302, 401, 403].includes(resp.status)) {
        info.isAlive = true;
        info.note = `HTTP ${resp.status}`;
      } else {
        info.note = `HTTP ${resp.status} (未命中目标状态码)`;
      }
      break;
    } catch {
      info.note = (info.note ? info.note + '; ' : '') + `${protocol.toUpperCase()} 探测失败`;
    }
  }

  return info;
}

/** 从 crt.sh 获取子域名 */
async function fetchCrtshSubdomains(rootDomain: string): Promise<string[]> {
  const url = `https://crt.sh/?q=%.${rootDomain}&output=json`;
  const resp = await fetch(url, {
    headers: { 'User-Agent': 'Mozilla/5.0' },
    signal: AbortSignal.timeout(15000)
  });

  if (!resp.ok) { return []; }

  const text = await resp.text();
  const entries = JSON.parse(text) as Array<{ name_value: string }>;
  const hosts = new Set<string>();

  for (const entry of entries) {
    const names = entry.name_value.split('\n');
    for (const name of names) {
      const clean = name.trim().toLowerCase();
      if (clean && clean.endsWith(`.${rootDomain}`) && !clean.includes('*')) {
        hosts.add(clean);
      }
    }
  }

  return Array.from(hosts);
}

/** 从目标 URL 提取根域名 */
export function extractRootDomain(url: string): string | null {
  try {
    const u = new URL(url);
    const parts = u.hostname.split('.');
    if (parts.length <= 2) { return u.hostname; }
    return parts.slice(-2).join('.');
  } catch {
    return null;
  }
}
