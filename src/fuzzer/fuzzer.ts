import { EndpointInfo, FuzzResult, FuzzConfig, FuzzProgress, SingleTestResult, TestType, RiskLevel } from '../types';
import * as payloads from './payloads';

/**
 * Fuzzer 测试引擎
 * 支持垂直测试（越权/IDOR/注入）和横向 Fuzz（多子域名）
 */
export async function runFuzz(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  onProgress: (progress: FuzzProgress) => void
): Promise<FuzzResult> {
  const tests: SingleTestResult[] = [];
  let testIndex = 0;

  const targetUrl = endpoint.fullUrl || endpoint.url || '';
  if (!targetUrl) {
    return {
      endpointId: endpoint.id,
      endpoint,
      targetHost: '',
      tests: [{
        testType: 'auth_bypass' as TestType,
        status: 'error',
        description: '无法测试：端点 URL 为空',
        requestInfo: `${endpoint.method} ${endpoint.path}`
      }],
      overallVulnerable: false,
      vulnerabilityLevel: 'info',
      timestamp: Date.now()
    };
  }

  const totalTests = countTests(config);
  onProgress({ phase: 'init', total: totalTests, completed: 0, message: `开始测试: ${endpoint.path}` });

  // 垂直测试（原域名）
  if (config.testAuthBypass) {
    onProgress({ phase: 'auth_bypass', total: totalTests, completed: testIndex, message: '越权测试中...' });
    const authResults = await testAuthBypass(endpoint, config);
    tests.push(...authResults);
    testIndex += authResults.length;
  }

  if (config.testIdor) {
    onProgress({ phase: 'idor', total: totalTests, completed: testIndex, message: 'IDOR 测试中...' });
    const idorResults = await testIdor(endpoint, config);
    tests.push(...idorResults);
    testIndex += idorResults.length;
  }

  if (config.testParamInject) {
    onProgress({ phase: 'param_inject', total: totalTests, completed: testIndex, message: '参数注入测试中...' });
    const injectResults = await testParamInjection(endpoint, config);
    tests.push(...injectResults);
    testIndex += injectResults.length;
  }

  if (config.testSqlInject) {
    onProgress({ phase: 'sql_inject', total: totalTests, completed: testIndex, message: 'SQL 注入测试中...' });
    const sqlResults = await testSqlInjection(endpoint, config);
    tests.push(...sqlResults);
    testIndex += sqlResults.length;
  }

  if (config.testSsrf) {
    onProgress({ phase: 'ssrf', total: totalTests, completed: testIndex, message: 'SSRF 测试中...' });
    const ssrfResults = await testSsrf(endpoint, config);
    tests.push(...ssrfResults);
    testIndex += ssrfResults.length;
  }

  // 横向 Fuzz
  if (config.testHorizontal) {
    onProgress({ phase: 'horizontal', total: totalTests, completed: testIndex, message: '横向 Fuzz 中...' });
    // 横向不在这里做（需要外层循环不同域名），这里标记
  }

  onProgress({ phase: 'done', total: totalTests, completed: testIndex, message: `测试完成: ${tests.filter(t => t.status === 'failed').length} 个漏洞` });

  const failedTests = tests.filter(t => t.status === 'failed');
  const vulnLevel: RiskLevel = failedTests.length >= 2 ? 'high'
    : failedTests.length >= 1 ? 'medium' : 'low';

  return {
    endpointId: endpoint.id,
    endpoint,
    targetHost: new URL(endpoint.fullUrl || endpoint.url || '').host || '',
    tests,
    overallVulnerable: failedTests.length > 0,
    vulnerabilityLevel: vulnLevel,
    timestamp: Date.now()
  };
}

/** 横向 Fuzz：同一端点打到多个子域名 */
export async function runHorizontalFuzz(
  endpoint: EndpointInfo,
  subdomains: string[],
  config: FuzzConfig,
  onProgress: (progress: FuzzProgress) => void
): Promise<FuzzResult[]> {
  const results: FuzzResult[] = [];
  let completed = 0;
  const total = subdomains.length;

  // 并发控制
  const batchSize = config.concurrentRequests;
  for (let i = 0; i < subdomains.length; i += batchSize) {
    const batch = subdomains.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (subdomain) => {
        const subUrl = replaceHost(endpoint.fullUrl || endpoint.url || '', subdomain);
        if (!subUrl) { return null; }

        const subEndpoint: EndpointInfo = { ...endpoint, fullUrl: subUrl };
        const testResult = await testAuthBypass(subEndpoint, config);

        completed++;
        onProgress({
          phase: 'horizontal',
          total,
          completed,
          message: `横向测试: ${subdomain} (${completed}/${total})`
        });

        const failed = testResult.filter(t => t.status === 'failed');
        return {
          endpointId: endpoint.id + '_' + subdomain,
          endpoint: subEndpoint,
          targetHost: subdomain,
          tests: testResult,
          overallVulnerable: failed.length > 0,
          vulnerabilityLevel: (failed.length >= 2 ? 'high' : failed.length >= 1 ? 'medium' : 'low') as RiskLevel,
          timestamp: Date.now()
        } as FuzzResult;
      })
    );

    for (const r of batchResults) {
      if (r) { results.push(r); }
    }
  }

  return results;
}

/** 越权测试 */
async function testAuthBypass(endpoint: EndpointInfo, config: FuzzConfig): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];

  for (const removeHeaders of payloads.AUTH_BYPASS_HEADERS) {
    try {
      const desc = Object.keys(removeHeaders).length === 0
        ? '移除所有认证头'
        : `修改认证头: ${JSON.stringify(removeHeaders)}`;

      const resp = await fetch(endpoint.fullUrl || endpoint.url, {
        method: endpoint.method,
        headers: { ...endpoint.headers, ...removeHeaders },
        signal: AbortSignal.timeout(config.timeout),
      });

      const body = await resp.text().catch(() => '');

      // 判断是否越权成功
      const isVulnerable = resp.status < 400 && !body.includes('unauthorized') && !body.includes('Unauthorized');

      results.push({
        testType: 'auth_bypass' as TestType,
        status: isVulnerable ? 'failed' : 'passed',
        description: desc,
        requestInfo: `${endpoint.method} ${endpoint.fullUrl}`,
        responseStatus: resp.status,
        responseBody: body.slice(0, 500),
        finding: isVulnerable ? `未授权访问成功! 状态码 ${resp.status}` : undefined
      });
    } catch (err: any) {
      results.push({
        testType: 'auth_bypass' as TestType,
        status: 'error',
        description: `越权测试异常: ${err.message}`,
        requestInfo: `${endpoint.method} ${endpoint.fullUrl}`
      });
    }
  }

  return results;
}

/** IDOR 测试 */
async function testIdor(endpoint: EndpointInfo, config: FuzzConfig): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const testUrl = endpoint.fullUrl || endpoint.url;

  for (const { pattern, name, replacer } of payloads.IDOR_ID_REPLACEMENTS) {
    const modifiedUrl = testUrl.replace(pattern, replacer);
    if (modifiedUrl === testUrl) { continue; }

    try {
      const resp = await fetch(modifiedUrl, {
        method: endpoint.method,
        headers: endpoint.headers,
        signal: AbortSignal.timeout(config.timeout),
      });

      const body = await resp.text().catch(() => '');

      // 返回了数据即为潜在 IDOR
      const isVulnerable = resp.status === 200 && body.length > 50;

      results.push({
        testType: 'idor' as TestType,
        status: isVulnerable ? 'failed' : 'passed',
        description: `IDOR ${name}: ${testUrl} → ${modifiedUrl}`,
        requestInfo: `${endpoint.method} ${modifiedUrl}`,
        responseStatus: resp.status,
        responseBody: body.slice(0, 500),
        finding: isVulnerable ? `IDOR 漏洞: 访问了其他用户数据 (${name})` : undefined
      });
    } catch (err: any) {
      results.push({
        testType: 'idor' as TestType,
        status: 'error',
        description: `IDOR 测试异常: ${err.message}`,
        requestInfo: `${endpoint.method} ${modifiedUrl}`
      });
    }
  }

  return results;
}

/** 参数注入测试 */
async function testParamInjection(endpoint: EndpointInfo, config: FuzzConfig): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];

  for (const payload of payloads.PARAM_INJECTION_PAYLOADS) {
    try {
      const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, 'test', payload.value);
      const resp = await fetch(testUrl, {
        method: endpoint.method,
        headers: endpoint.headers,
        signal: AbortSignal.timeout(config.timeout),
      });

      const body = await resp.text().catch(() => '');
      const isVulnerable = checkInjectionResponse(body, payload.name);

      results.push({
        testType: 'param_inject' as TestType,
        status: isVulnerable ? 'failed' : 'passed',
        description: `参数注入: ${payload.description}`,
        requestInfo: `${endpoint.method} ${testUrl}`,
        responseStatus: resp.status,
        responseBody: body.slice(0, 500),
        finding: isVulnerable ? `参数注入: ${payload.description} 触发异常响应` : undefined
      });
    } catch (err: any) {
      results.push({
        testType: 'param_inject' as TestType,
        status: 'error',
        description: `参数注入异常: ${err.message}`,
        requestInfo: `${endpoint.method} ${endpoint.fullUrl}`
      });
    }
  }

  return results;
}

/** SQL 注入测试 */
async function testSqlInjection(endpoint: EndpointInfo, config: FuzzConfig): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];

  for (const payload of payloads.SQL_INJECTION_PAYLOADS) {
    try {
      const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, 'id', payload.value);
      const startTime = Date.now();
      const resp = await fetch(testUrl, {
        method: endpoint.method,
        headers: endpoint.headers,
        signal: AbortSignal.timeout(config.timeout),
      });
      const elapsed = Date.now() - startTime;

      const body = await resp.text().catch(() => '');

      // SQL 错误特征
      const sqlErrors = [
        'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
        'syntax error', 'unclosed quotation', 'ODBC',
        'SQLSTATE', 'warning.*mysql', 'mySQLException',
        'PostgreSQL.*ERROR', 'Driver.*SQL',
      ];

      const hasSqlError = sqlErrors.some(e => body.toLowerCase().includes(e));
      const isTimeBased = payload.name === 'sleep' && elapsed > 1500;
      const isVulnerable = hasSqlError || isTimeBased || resp.status === 500;

      results.push({
        testType: 'sql_inject' as TestType,
        status: isVulnerable ? 'failed' : 'passed',
        description: `SQL 注入: ${payload.description}`,
        requestInfo: `${endpoint.method} ${testUrl}`,
        responseStatus: resp.status,
        responseBody: body.slice(0, 500),
        finding: isVulnerable ? `SQL 注入: ${payload.description} (耗时${elapsed}ms)` : undefined
      });
    } catch (err: any) {
      results.push({
        testType: 'sql_inject' as TestType,
        status: 'error',
        description: `SQL 注入异常: ${err.message}`,
        requestInfo: `${endpoint.method} ${endpoint.fullUrl}`
      });
    }
  }

  return results;
}

/** SSRF 测试 */
async function testSsrf(endpoint: EndpointInfo, config: FuzzConfig): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const ssrfParams = ['url', 'redirect', 'path', 'callback', 'next', 'return_to', 'redirect_url'];

  for (const param of ssrfParams) {
    for (const payload of payloads.SSRF_PAYLOADS) {
      try {
        const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, param, payload.value);
        const resp = await fetch(testUrl, {
          method: endpoint.method,
          headers: endpoint.headers,
          signal: AbortSignal.timeout(config.timeout),
          redirect: 'manual',
        });

        const body = await resp.text().catch(() => '');

        // SSRF 特征
        const ssrfIndicators = [
          'root:', 'daemon:', '/bin/bash', '/etc/passwd',
          'ami-id', 'instance-id', 'security-groups', 'meta-data'
        ];
        const hasSsrfIndicator = ssrfIndicators.some(e => body.toLowerCase().includes(e.toLowerCase()));

        results.push({
          testType: 'ssrf' as TestType,
          status: hasSsrfIndicator ? 'failed' : 'passed',
          description: `SSRF ${payload.description}: param=${param}`,
          requestInfo: `${endpoint.method} ${testUrl}`,
          responseStatus: resp.status,
          responseBody: body.slice(0, 500),
          finding: hasSsrfIndicator ? `SSRF 漏洞: ${payload.description}` : undefined
        });
      } catch (err: any) {
        results.push({
          testType: 'ssrf' as TestType,
          status: 'error',
          description: `SSRF 异常: ${err.message}`,
          requestInfo: `${endpoint.method} ${endpoint.fullUrl}`
        });
      }
    }
  }

  return results;
}

// 辅助函数

/** 替换 URL 中的 Host */
function replaceHost(url: string, newHost: string): string | null {
  try {
    const u = new URL(url);
    u.hostname = newHost;
    return u.toString();
  } catch {
    return null;
  }
}

/** 添加查询参数 */
function appendQueryParam(url: string, key: string, value: string): string {
  try {
    const u = new URL(url);
    u.searchParams.set(key, value);
    return u.toString();
  } catch {
    if (url.includes('?')) {
      return `${url}&${key}=${encodeURIComponent(value)}`;
    }
    return `${url}?${key}=${encodeURIComponent(value)}`;
  }
}

/** 检查注入响应 */
function checkInjectionResponse(body: string, payloadName: string): boolean {
  if (body.length === 0) { return false; }

  const lower = body.toLowerCase();

  switch (payloadName) {
    case 'xss_basic':
    case 'xss_img':
      return body.includes('<script>alert') || body.includes('onerror=alert');
    case 'prototype_pollution':
      return lower.includes('admin') && lower.includes('true');
    case 'path_traversal':
      return lower.includes('root:') || lower.includes('passwd');
    default:
      return false;
  }
}

/** 计算总测试数 */
function countTests(config: FuzzConfig): number {
  let count = 0;
  if (config.testAuthBypass) { count += payloads.AUTH_BYPASS_HEADERS.length; }
  if (config.testIdor) { count += payloads.IDOR_ID_REPLACEMENTS.length; }
  if (config.testParamInject) { count += payloads.PARAM_INJECTION_PAYLOADS.length; }
  if (config.testSqlInject) { count += payloads.SQL_INJECTION_PAYLOADS.length; }
  if (config.testSsrf) { count += payloads.SSRF_PAYLOADS.length * 7; } // 7 SSR params
  return count;
}
