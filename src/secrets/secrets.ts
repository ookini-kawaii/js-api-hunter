/**
 * SecretFinder - 从 JS 文件中提取敏感信息
 * 对应 PDF 第 4 章：用 SecretFinder 扫密钥
 */

import { JsFile, SecretFinding, RiskLevel } from '../types';

export interface SecretPattern {
  type: string;
  name: string;
  regex: RegExp;
  riskLevel: RiskLevel;
  /** 是否对匹配值做掩码处理 */
  mask?: boolean;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    type: 'cloud_key',
    name: '阿里云 AccessKey',
    regex: /(LTAI[a-zA-Z0-9]{12,20})/g,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'cloud_key',
    name: 'AWS AccessKeyId',
    regex: /(AKIA[0-9A-Z]{16})/g,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'private_key',
    name: '私钥文件',
    regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{50,500}?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    riskLevel: 'high',
    mask: false
  },
  {
    type: 'api_key',
    name: 'API Key',
    regex: /(?:api[_-]?key|apikey|app[_-]?key|appkey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'secret',
    name: 'Secret / SecretKey',
    regex: /(?:secret[_-]?key|secretkey|app[_-]?secret|appsecret|client_secret)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'password',
    name: '硬编码密码',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']/gi,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'jwt',
    name: 'JWT Secret',
    regex: /(?:jwt[_-]?secret|jwtsecret|token[_-]?secret)\s*[:=]\s*["']([^"']{8,})["']/gi,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'token',
    name: '硬编码 Token',
    regex: /(?:access[_-]?token|refresh[_-]?token|auth[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{20,})["']/gi,
    riskLevel: 'high',
    mask: true
  },
  {
    type: 'authorization',
    name: 'Authorization Header',
    regex: /["']Authorization["']\s*[:=]\s*["']([a-zA-Z0-9_\-\.\s]{20,})["']/gi,
    riskLevel: 'medium',
    mask: true
  },
  {
    type: 'internal_domain',
    name: '内部域名',
    regex: /https?:\/\/([a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]{2,})/gi,
    riskLevel: 'medium',
    mask: false
  }
];

/** 对敏感值做掩码，保留前 4 后 4 */
function maskValue(value: string): string {
  if (value.length <= 10) { return '*'.repeat(value.length); }
  return value.slice(0, 4) + '****' + value.slice(-4);
}

/** 从所有 JS 文件中提取敏感信息 */
export function extractSecrets(jsFiles: JsFile[], targetDomain?: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();

  for (const file of jsFiles) {
    for (const pattern of SECRET_PATTERNS) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', '') + 'g');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(file.content)) !== null) {
        const rawValue = match[1] ?? match[0];
        const value = typeof rawValue === 'string' ? rawValue.trim() : rawValue;

        // 去重：按 类型+值+文件 去重
        const key = `${pattern.type}:${value}:${file.url}`;
        if (seen.has(key)) { continue; }
        seen.add(key);

        // 内部域名过滤：只保留与目标域名不同但同根的二级/三级域名
        if (pattern.type === 'internal_domain') {
          if (!isInterestingDomain(value, targetDomain)) { continue; }
        }

        const displayValue = pattern.mask ? maskValue(value) : value;
        const snippetStart = Math.max(0, match.index - 40);
        const snippetEnd = Math.min(file.content.length, match.index + value.length + 40);
        const snippet = file.content.slice(snippetStart, snippetEnd).replace(/\s+/g, ' ');

        findings.push({
          type: pattern.type,
          name: pattern.name,
          value: displayValue,
          sourceFile: file.url,
          snippet,
          riskLevel: pattern.riskLevel
        });
      }
    }
  }

  return findings;
}

/** 判断域名是否值得关注 */
function isInterestingDomain(domain: string, targetDomain?: string): boolean {
  if (!targetDomain) { return true; }
  // 只保留同根域名的子域名
  const root = targetDomain.replace(/^www\./, '').toLowerCase();
  const d = domain.toLowerCase();
  return d !== targetDomain.toLowerCase() && d.endsWith('.' + root);
}

/** 从敏感信息中提取唯一内部域名列表 */
export function extractInternalDomains(findings: SecretFinding[]): string[] {
  const domains = new Set<string>();
  for (const f of findings) {
    if (f.type === 'internal_domain') {
      // value 此时是完整 URL，需要提取 host
      const match = f.value.match(/https?:\/\/([^/]+)/);
      if (match) { domains.add(match[1]); }
    }
  }
  return Array.from(domains);
}
