/**
 * Fuzzer 测试引擎
 * 支持垂直测试（越权/IDOR/注入/Mass Assignment/业务逻辑）和横向 Fuzz（多子域名 + 路径变异）
 */

import { EndpointInfo, FuzzResult, FuzzConfig, FuzzProgress, SingleTestResult, TestType, RiskLevel } from '../types';
import * as payloads from './payloads';

/**
 * 运行单接口垂直测试
 */
export async function runFuzz(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  onProgress: (progress: FuzzProgress) => void
): Promise<FuzzResult> {
  const tests: SingleTestResult[] = [];

  const targetUrl = endpoint.fullUrl || endpoint.url || '';
  if (!targetUrl) {
    return errorResult(endpoint, '无法测试：端点 URL 为空');
  }

  const totalTests = countTests(config);
  onProgress({ phase: 'init', total: totalTests, completed: 0, message: `开始测试: ${endpoint.path}` });

  // 先打一条带 Token 的基准请求（PDF 强调：先确认原请求能通）
  const baseline = await fetchBaseline(endpoint, config);

  // 鉴权维度（最高出洞率）：带 Token 基准 + 删 Token + 改 Token
  if (config.testAuthBypass) {
    onProgress({ phase: 'auth_bypass', total: totalTests, completed: tests.length, message: '越权测试中...' });
    const authResults = await testAuthBypass(endpoint, config, baseline);
    tests.push(...authResults);
  }

  // URL 路径 IDOR
  if (config.testIdor) {
    onProgress({ phase: 'idor', total: totalTests, completed: tests.length, message: 'IDOR 测试中...' });
    const idorResults = await testIdor(endpoint, config, baseline);
    tests.push(...idorResults);
  }

  // Body / Query IDOR
  if (config.testIdorBody) {
    onProgress({ phase: 'idor_body', total: totalTests, completed: tests.length, message: 'Body/Query IDOR 测试中...' });
    const idorBodyResults = await testIdorBody(endpoint, config, baseline);
    tests.push(...idorBodyResults);
  }

  // 参数注入
  if (config.testParamInject) {
    onProgress({ phase: 'param_inject', total: totalTests, completed: tests.length, message: '参数注入测试中...' });
    const injectResults = await testParamInjection(endpoint, config, baseline);
    tests.push(...injectResults);
  }

  // SQL 注入
  if (config.testSqlInject) {
    onProgress({ phase: 'sql_inject', total: totalTests, completed: tests.length, message: 'SQL 注入测试中...' });
    const sqlResults = await testSqlInjection(endpoint, config, baseline);
    tests.push(...sqlResults);
  }

  // NoSQL 注入
  if (config.testNoSqlInject) {
    onProgress({ phase: 'nosql_inject', total: totalTests, completed: tests.length, message: 'NoSQL 注入测试中...' });
    const noSqlResults = await testNoSqlInjection(endpoint, config, baseline);
    tests.push(...noSqlResults);
  }

  // SSRF
  if (config.testSsrf) {
    onProgress({ phase: 'ssrf', total: totalTests, completed: tests.length, message: 'SSRF 测试中...' });
    const ssrfResults = await testSsrf(endpoint, config, baseline);
    tests.push(...ssrfResults);
  }

  // Mass Assignment
  if (config.testMassAssignment) {
    onProgress({ phase: 'mass_assignment', total: totalTests, completed: tests.length, message: 'Mass Assignment 测试中...' });
    const massResults = await testMassAssignment(endpoint, config, baseline);
    tests.push(...massResults);
  }

  // 业务逻辑
  if (config.testBusinessLogic) {
    onProgress({ phase: 'business_logic', total: totalTests, completed: tests.length, message: '业务逻辑测试中...' });
    const bizResults = await testBusinessLogic(endpoint, config, baseline);
    tests.push(...bizResults);
  }

  // 接口滥用
  if (config.testInterfaceAbuse) {
    onProgress({ phase: 'interface_abuse', total: totalTests, completed: tests.length, message: '接口滥用测试中...' });
    const abuseResults = await testInterfaceAbuse(endpoint, config, baseline);
    tests.push(...abuseResults);
  }

  // 并发/竞态
  if (config.testRaceCondition) {
    onProgress({ phase: 'race_condition', total: totalTests, completed: tests.length, message: '并发竞态测试中...' });
    const raceResults = await testRaceCondition(endpoint, config, baseline);
    tests.push(...raceResults);
  }

  // 签名绕过
  if (config.testSignBypass) {
    onProgress({ phase: 'sign_bypass', total: totalTests, completed: tests.length, message: '签名绕过测试中...' });
    const signResults = await testSignBypass(endpoint, config, baseline);
    tests.push(...signResults);
  }

  onProgress({ phase: 'done', total: totalTests, completed: tests.length, message: `测试完成: ${tests.filter(t => t.status === 'failed').length} 个漏洞` });

  const failedTests = tests.filter(t => t.status === 'failed');
  const vulnLevel: RiskLevel = failedTests.length >= 3 ? 'high'
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

  // 路径变异 + 子域名 = 二维矩阵
  const pathVariants = config.pathVariants
    ? payloads.generatePathVariants(endpoint.path)
    : [endpoint.path];

  const total = subdomains.length * pathVariants.length;

  const batchSize = config.concurrentRequests;
  for (const pathVariant of pathVariants) {
    for (let i = 0; i < subdomains.length; i += batchSize) {
      const batch = subdomains.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(async (subdomain) => {
          const subUrl = buildSubUrl(endpoint, subdomain, pathVariant);
          if (!subUrl) { return null; }

          const subEndpoint: EndpointInfo = { ...endpoint, fullUrl: subUrl, path: pathVariant };

          // 对横向目标跑完整垂直测试（含带/不带 Token 两个版本）
          const testResult = await runFuzz(subEndpoint, config, () => {});

          completed++;
          onProgress({
            phase: 'horizontal',
            total,
            completed,
            message: `横向测试: ${subdomain}${pathVariant !== endpoint.path ? ' [' + pathVariant + ']' : ''} (${completed}/${total})`
          });

          return testResult;
        })
      );

      for (const r of batchResults) {
        if (r) { results.push(r); }
      }
    }
  }

  return results;
}

// ==================== 垂直测试实现 ====================

/** 带 Token 基准请求 */
async function fetchBaseline(endpoint: EndpointInfo, config: FuzzConfig): Promise<{ status: number; body: string; length: number }> {
  const headers = buildHeaders(config.userToken);
  try {
    const resp = await fetch(endpoint.fullUrl || endpoint.url, {
      method: endpoint.method,
      headers,
      signal: AbortSignal.timeout(config.timeout),
    });
    const body = await resp.text().catch(() => '');
    return { status: resp.status, body, length: body.length };
  } catch {
    return { status: 0, body: '', length: 0 };
  }
}

/** 越权测试：删除/篡改 Token */
async function testAuthBypass(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];

  // 先测带 Token 基准
  results.push(await singleRequest(
    endpoint,
    buildHeaders(config.userToken),
    config,
    'auth_bypass',
    '带 Token 基准请求',
    baseline
  ));

  // 再测各种绕过 header
  for (const removeHeaders of payloads.AUTH_BYPASS_HEADERS) {
    const headers = { ...buildHeaders(config.userToken), ...removeHeaders };
    const desc = Object.keys(removeHeaders).length === 0
      ? '移除所有认证头（裸奔）'
      : `篡改认证头: ${JSON.stringify(removeHeaders)}`;

    const result = await singleRequest(endpoint, headers, config, 'auth_bypass', desc, baseline);
    results.push(result);
  }

  return results;
}

/** URL 路径 IDOR */
async function testIdor(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const testUrl = endpoint.fullUrl || endpoint.url;

  for (const { pattern, name, replacer } of payloads.IDOR_ID_REPLACEMENTS) {
    const modifiedUrl = testUrl.replace(pattern, replacer as any);
    if (modifiedUrl === testUrl) { continue; }

    const result = await singleRequest(
      { ...endpoint, fullUrl: modifiedUrl, path: modifiedUrl },
      buildHeaders(config.userToken),
      config,
      'idor',
      `IDOR ${name}: ${endpoint.path} → ${modifiedUrl}`,
      baseline,
      modifiedUrl
    );

    // IDOR 命中：返回了数据且不是基准自身
    if (result.status === 'passed' || result.status === 'error') {
      results.push(result);
      continue;
    }
    const isDataLeak = result.responseStatus === 200 && (result.responseBody?.length || 0) > 50;
    if (isDataLeak) {
      result.finding = `IDOR 漏洞: 访问了其他用户数据 (${name})`;
      result.status = 'failed';
    }
    results.push(result);
  }

  return results;
}

/** Body / Query IDOR：改 userId / orderId 等参数 */
async function testIdorBody(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const params = buildBaseParams(endpoint);
  const paramNames = Object.keys(params);

  if (paramNames.length === 0) { return results; }

  for (const paramName of paramNames) {
    for (const newValue of payloads.IDOR_BODY_VALUES) {
      const testParams = { ...params, [paramName]: newValue };
      const result = await requestWithParams(
        endpoint,
        buildHeaders(config.userToken),
        testParams,
        config,
        'idor_body',
        `Body/Query IDOR: ${paramName}=${newValue}`,
        baseline
      );

      const isDataLeak = result.responseStatus === 200 && (result.responseBody?.length || 0) > 50;
      if (isDataLeak) {
        result.finding = `Body/Query IDOR: ${paramName}=${newValue} 返回了数据`;
        result.status = 'failed';
      }
      results.push(result);
    }
  }

  // PDF 强调：两账号对比是越权测试核心
  if (config.comparisonToken) {
    const result = await requestWithParams(
      endpoint,
      buildHeaders(config.comparisonToken),
      params,
      config,
      'idor_body',
      'Body/Query IDOR: 账号 B Token 访问账号 A 数据',
      baseline
    );

    const isCrossAccount = result.responseStatus === 200 &&
      (result.responseBody?.length || 0) > 50 &&
      result.responseBody !== baseline.body;
    if (isCrossAccount) {
      result.finding = '水平越权: 使用账号 B Token 可访问账号 A 的数据';
      result.status = 'failed';
    }
    results.push(result);
  }

  return results;
}

/** 参数注入测试 */
async function testParamInjection(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];

  for (const payload of payloads.PARAM_INJECTION_PAYLOADS) {
    const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, 'test', payload.value);
    const result = await singleRequest(
      { ...endpoint, fullUrl: testUrl },
      buildHeaders(config.userToken),
      config,
      'param_inject',
      `参数注入: ${payload.description}`,
      baseline,
      testUrl
    );

    if (checkInjectionResponse(result.responseBody || '', payload.name)) {
      result.status = 'failed';
      result.finding = `参数注入: ${payload.description} 触发异常响应`;
    }
    results.push(result);
  }

  return results;
}

/** SQL 注入测试 */
async function testSqlInjection(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];

  for (const payload of payloads.SQL_INJECTION_PAYLOADS) {
    const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, 'id', payload.value);
    const startTime = Date.now();
    const result = await singleRequest(
      { ...endpoint, fullUrl: testUrl },
      buildHeaders(config.userToken),
      config,
      'sql_inject',
      `SQL 注入: ${payload.description}`,
      baseline,
      testUrl
    );
    const elapsed = Date.now() - startTime;

    const sqlErrors = [
      'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
      'syntax error', 'unclosed quotation', 'ODBC',
      'SQLSTATE', 'warning.*mysql', 'mySQLException',
      'PostgreSQL.*ERROR', 'Driver.*SQL',
    ];
    const hasSqlError = sqlErrors.some(e => (result.responseBody || '').toLowerCase().includes(e));
    const isTimeBased = payload.name === 'sleep' && elapsed > 1500;

    if (hasSqlError || isTimeBased || result.responseStatus === 500) {
      result.status = 'failed';
      result.finding = `SQL 注入: ${payload.description} (耗时${elapsed}ms)`;
    }
    results.push(result);
  }

  return results;
}

/** NoSQL 注入测试 */
async function testNoSqlInjection(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const noSqlParams = ['id', 'userId', 'orderId', 'query', 'filter', 'where'];

  for (const param of noSqlParams) {
    for (const payload of payloads.NOSQL_INJECTION_PAYLOADS) {
      const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, param, payload.value);
      const result = await singleRequest(
        { ...endpoint, fullUrl: testUrl },
        buildHeaders(config.userToken),
        config,
        'nosql_inject',
        `NoSQL 注入: ${payload.description} (param=${param})`,
        baseline,
        testUrl
      );

      const noSqlErrors = ['mongo', 'mongodb', 'casterror', 'validationerror', '$ne', '$gt'];
      const hasNoSqlError = noSqlErrors.some(e => (result.responseBody || '').toLowerCase().includes(e));
      const isUnexpectedSuccess = result.responseStatus === 200 &&
        (result.responseBody?.length || 0) > 20 &&
        result.responseBody !== baseline.body;

      if (hasNoSqlError || isUnexpectedSuccess) {
        result.status = 'failed';
        result.finding = `NoSQL 注入: ${payload.description}`;
      }
      results.push(result);
    }
  }

  return results;
}

/** SSRF 测试 */
async function testSsrf(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const ssrfParams = ['url', 'redirect', 'path', 'callback', 'next', 'return_to', 'redirect_url', 'target'];

  for (const param of ssrfParams) {
    for (const payload of payloads.SSRF_PAYLOADS) {
      const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, param, payload.value);
      const result = await singleRequest(
        { ...endpoint, fullUrl: testUrl },
        buildHeaders(config.userToken),
        config,
        'ssrf',
        `SSRF ${payload.description}: param=${param}`,
        baseline,
        testUrl
      );

      const ssrfIndicators = [
        'root:', 'daemon:', '/bin/bash', '/etc/passwd',
        'ami-id', 'instance-id', 'security-groups', 'meta-data'
      ];
      const hasSsrfIndicator = ssrfIndicators.some(e =>
        (result.responseBody || '').toLowerCase().includes(e.toLowerCase())
      );

      if (hasSsrfIndicator) {
        result.status = 'failed';
        result.finding = `SSRF 漏洞: ${payload.description}`;
      }
      results.push(result);
    }
  }

  return results;
}

/** Mass Assignment 测试 */
async function testMassAssignment(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const baseParams = buildBaseParams(endpoint);

  for (const payload of payloads.MASS_ASSIGNMENT_PAYLOADS) {
    const testParams = { ...baseParams, [payload.field]: payload.value };
    const result = await requestWithParams(
      endpoint,
      buildHeaders(config.userToken),
      testParams,
      config,
      'mass_assignment',
      `Mass Assignment: ${payload.description}`,
      baseline
    );

    // 命中：返回成功且响应体与基准不同（可能改动了数据）
    if (result.responseStatus && result.responseStatus < 400 &&
        (result.responseBody?.length || 0) > 0 &&
        result.responseBody !== baseline.body) {
      result.status = 'failed';
      result.finding = `Mass Assignment 命中: ${payload.description}`;
    }
    results.push(result);
  }

  return results;
}

/** 业务逻辑测试 */
async function testBusinessLogic(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const baseParams = buildBaseParams(endpoint);

  for (const payload of payloads.BUSINESS_LOGIC_PAYLOADS) {
    const testParams = { ...baseParams, [payload.field]: payload.value };
    const result = await requestWithParams(
      endpoint,
      buildHeaders(config.userToken),
      testParams,
      config,
      'business_logic',
      `业务逻辑: ${payload.description}`,
      baseline
    );

    // 命中：状态码成功且没有明显错误
    if (result.responseStatus && result.responseStatus < 400 &&
        (result.responseBody?.length || 0) > 0 &&
        !isUnauthorizedResponse(result.responseBody || '')) {
      result.status = 'failed';
      result.finding = `业务逻辑异常: ${payload.description}`;
    }
    results.push(result);
  }

  return results;
}

/** 接口滥用测试：短信轰炸、验证码爆破、优惠券重复领取 */
async function testInterfaceAbuse(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const abuseParams = ['phone', 'email', 'mobile', 'code', 'verifyCode', 'coupon', 'couponCode', 'draw', 'lottery'];

  for (const param of abuseParams) {
    for (const payload of payloads.INTERFACE_ABUSE_PAYLOADS) {
      const testUrl = appendQueryParam(endpoint.fullUrl || endpoint.url, param, payload.value);
      const result = await singleRequest(
        { ...endpoint, fullUrl: testUrl },
        buildHeaders(config.userToken),
        config,
        'interface_abuse',
        `接口滥用: ${payload.description} (param=${param})`,
        baseline,
        testUrl
      );

      // 命中：请求成功且无频率限制提示
      if (result.responseStatus === 200 &&
          (result.responseBody?.length || 0) > 0 &&
          !isRateLimitedResponse(result.responseBody || '')) {
        result.status = 'failed';
        result.finding = `接口滥用风险: ${payload.description}`;
      }
      results.push(result);
    }
  }

  return results;
}

/** 并发/竞态测试：同一请求短时间并发发送 */
async function testRaceCondition(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const concurrentCount = Math.min(config.concurrentRequests, 10);

  try {
    const startTime = Date.now();
    const responses = await Promise.all(
      Array.from({ length: concurrentCount }, () =>
        fetch(endpoint.fullUrl || endpoint.url, {
          method: endpoint.method,
          headers: buildHeaders(config.userToken),
          signal: AbortSignal.timeout(config.timeout)
        }).then(r => r.text().catch(() => '')).catch(() => '')
      )
    );
    const elapsed = Date.now() - startTime;

    const successCount = responses.filter(r => r.length > 0 && !isUnauthorizedResponse(r)).length;
    const hasRaceCondition = successCount >= concurrentCount * 0.8 && successCount > 1;

    results.push({
      testType: 'race_condition',
      status: hasRaceCondition ? 'failed' : 'passed',
      description: `并发竞态: ${concurrentCount} 次并发请求`,
      requestInfo: `${endpoint.method} ${endpoint.fullUrl || endpoint.url}`,
      responseStatus: 200,
      responseBody: `成功响应 ${successCount}/${concurrentCount}，耗时 ${elapsed}ms`,
      finding: hasRaceCondition ? `并发竞态风险: ${successCount}/${concurrentCount} 次请求均成功，可能存在重复领取/竞态漏洞` : undefined
    });
  } catch (err: any) {
    results.push({
      testType: 'race_condition',
      status: 'error',
      description: `并发竞态测试异常: ${err.message}`,
      requestInfo: `${endpoint.method} ${endpoint.fullUrl || endpoint.url}`
    });
  }

  return results;
}

/** 签名绕过测试：删除签名字段/头，老系统可能不校验 */
async function testSignBypass(
  endpoint: EndpointInfo,
  config: FuzzConfig,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult[]> {
  const results: SingleTestResult[] = [];
  const baseUrl = endpoint.fullUrl || endpoint.url;

  // 1. 删除签名头
  for (const signHeaders of payloads.SIGN_BYPASS_HEADERS) {
    const headers = { ...buildHeaders(config.userToken) };
    for (const [k] of Object.entries(signHeaders)) {
      delete headers[k];
    }

    const result = await singleRequest(
      endpoint,
      headers,
      config,
      'sign_bypass',
      `签名绕过: 删除头 ${Object.keys(signHeaders).join(',')}`,
      baseline
    );

    if (result.responseStatus === 200 &&
        (result.responseBody?.length || 0) > 20 &&
        !isUnauthorizedResponse(result.responseBody || '')) {
      result.status = 'failed';
      result.finding = `签名绕过: 删除 ${Object.keys(signHeaders).join(',')} 后仍可访问`;
    }
    results.push(result);
  }

  // 2. 删除 URL 签名参数
  for (const param of payloads.SIGN_BYPASS_PARAMS) {
    const testUrl = removeQueryParam(baseUrl, param);
    if (testUrl === baseUrl) { continue; }

    const result = await singleRequest(
      { ...endpoint, fullUrl: testUrl },
      buildHeaders(config.userToken),
      config,
      'sign_bypass',
      `签名绕过: 删除 URL 参数 ${param}`,
      baseline,
      testUrl
    );

    if (result.responseStatus === 200 &&
        (result.responseBody?.length || 0) > 20 &&
        !isUnauthorizedResponse(result.responseBody || '')) {
      result.status = 'failed';
      result.finding = `签名绕过: 删除 URL 参数 ${param} 后仍可访问`;
    }
    results.push(result);
  }

  return results;
}

// ==================== 请求辅助函数 ====================

/** 发送一次请求并返回结果 */
async function singleRequest(
  endpoint: EndpointInfo,
  headers: Record<string, string>,
  config: FuzzConfig,
  testType: TestType,
  description: string,
  baseline: { status: number; body: string; length: number },
  testUrl?: string
): Promise<SingleTestResult> {
  const url = testUrl || endpoint.fullUrl || endpoint.url;
  try {
    const resp = await fetch(url, {
      method: endpoint.method,
      headers,
      signal: AbortSignal.timeout(config.timeout),
    });

    const body = await resp.text().catch(() => '');
    const isVulnerable = judgeVulnerable(resp.status, body, baseline, testType);

    return {
      testType,
      status: isVulnerable ? 'failed' : 'passed',
      description,
      requestInfo: `${endpoint.method} ${url}`,
      testUrl: url,
      responseStatus: resp.status,
      responseBody: body.slice(0, 500),
      finding: isVulnerable ? `${description} 疑似成功 (状态码 ${resp.status})` : undefined
    };
  } catch (err: any) {
    return {
      testType,
      status: 'error',
      description: `${description} 异常: ${err.message}`,
      requestInfo: `${endpoint.method} ${url}`,
      testUrl: url
    };
  }
}

/** 发送带参数的请求（GET query / POST JSON） */
async function requestWithParams(
  endpoint: EndpointInfo,
  headers: Record<string, string>,
  params: Record<string, any>,
  config: FuzzConfig,
  testType: TestType,
  description: string,
  baseline: { status: number; body: string; length: number }
): Promise<SingleTestResult> {
  const url = endpoint.fullUrl || endpoint.url;
  const method = endpoint.method.toUpperCase();

  try {
    let resp: Response;
    if (method === 'GET') {
      const u = new URL(url);
      for (const [k, v] of Object.entries(params)) {
        u.searchParams.set(k, String(v));
      }
      resp = await fetch(u.toString(), {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(config.timeout),
      });
    } else {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      resp = await fetch(url, {
        method,
        headers,
        body: JSON.stringify(params),
        signal: AbortSignal.timeout(config.timeout),
      });
    }

    const body = await resp.text().catch(() => '');
    const isVulnerable = judgeVulnerable(resp.status, body, baseline, testType);

    return {
      testType,
      status: isVulnerable ? 'failed' : 'passed',
      description,
      requestInfo: `${method} ${url} | ${JSON.stringify(params)}`,
      testUrl: url,
      responseStatus: resp.status,
      responseBody: body.slice(0, 500),
      finding: isVulnerable ? `${description} 疑似成功 (状态码 ${resp.status})` : undefined
    };
  } catch (err: any) {
    return {
      testType,
      status: 'error',
      description: `${description} 异常: ${err.message}`,
      requestInfo: `${method} ${url}`,
      testUrl: url
    };
  }
}

/** 判断响应是否表示漏洞存在 */
function judgeVulnerable(
  status: number,
  body: string,
  baseline: { status: number; body: string; length: number },
  testType: TestType
): boolean {
  // 错误响应不算漏洞
  if (status >= 500) { return false; }

  // 认证绕过：无 Token 情况下返回与基准类似的成功响应
  if (testType === 'auth_bypass') {
    const hasAuthError = isUnauthorizedResponse(body);
    return status < 400 && !hasAuthError && body.length > 10;
  }

  // IDOR / Mass Assignment / 业务逻辑 / 签名绕过：返回 200 且有数据，且没有未授权关键字
  if (
    testType === 'idor' ||
    testType === 'idor_body' ||
    testType === 'mass_assignment' ||
    testType === 'business_logic' ||
    testType === 'sign_bypass'
  ) {
    return status === 200 && body.length > 20 && !isUnauthorizedResponse(body);
  }

  // 接口滥用：返回 200 且无频率限制提示
  if (testType === 'interface_abuse') {
    return status === 200 && body.length > 0 && !isRateLimitedResponse(body);
  }

  // 注入类：由调用方根据特征二次判断，这里只给基础通过/失败
  return status === 200 && body.length > 0;
}

/** 构建请求头 */
function buildHeaders(token?: string): Record<string, string> {
  const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
  if (token) {
    headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }
  return headers;
}

/** 构建基础参数：优先用 endpoint.parameters，否则从路径提取 id */
function buildBaseParams(endpoint: EndpointInfo): Record<string, any> {
  if (endpoint.parameters.length > 0) {
    const params: Record<string, any> = {};
    for (const p of endpoint.parameters) {
      params[p.name] = p.defaultValue ?? (p.type === 'number' ? 1 : 'test');
    }
    return params;
  }

  // 从路径最后一位数字推断 id
  const numMatch = endpoint.path.match(/\/(\d+)(?:\/|$)/);
  const id = numMatch ? Number(numMatch[1]) : 1;
  return { id };
}

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

/** 删除 URL 查询参数 */
function removeQueryParam(url: string, key: string): string {
  try {
    const u = new URL(url);
    u.searchParams.delete(key);
    return u.toString();
  } catch {
    return url;
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
      return lower.includes('root:') || lower.includes('/etc/passwd');
    case 'nosql_inject':
      return lower.includes('$ne') || lower.includes('mongo');
    default:
      return false;
  }
}

/** 检查响应是否包含未授权错误 */
function isUnauthorizedResponse(body: string): boolean {
  const lower = body.toLowerCase();
  return payloads.UNAUTHORIZED_KEYWORDS.some(k => lower.includes(k));
}

/** 检查响应是否包含频率限制提示 */
function isRateLimitedResponse(body: string): boolean {
  const lower = body.toLowerCase();
  const rateLimitKeywords = [
    'too many', 'rate limit', 'too many requests', 'frequency',
    'frequent', 'try again later', 'cooldown', 'throttle',
    '请求过于频繁', '频率限制', '请稍后再试', '操作过于频繁'
  ];
  return rateLimitKeywords.some(k => lower.includes(k));
}

/** 构造横向测试 URL */
function buildSubUrl(endpoint: EndpointInfo, subdomain: string, pathVariant: string): string | null {
  const baseUrl = endpoint.fullUrl || endpoint.url;
  if (!baseUrl) { return null; }

  try {
    const u = new URL(baseUrl);
    u.hostname = subdomain;
    u.pathname = pathVariant;
    return u.toString();
  } catch {
    return null;
  }
}

/** 错误结果 */
function errorResult(endpoint: EndpointInfo, message: string): FuzzResult {
  return {
    endpointId: endpoint.id,
    endpoint,
    targetHost: '',
    tests: [{
      testType: 'auth_bypass',
      status: 'error',
      description: message,
      requestInfo: `${endpoint.method} ${endpoint.path}`
    }],
    overallVulnerable: false,
    vulnerabilityLevel: 'info',
    timestamp: Date.now()
  };
}

/** 计算总测试数 */
function countTests(config: FuzzConfig): number {
  let count = 0;
  if (config.testAuthBypass) { count += payloads.AUTH_BYPASS_HEADERS.length + 1; }
  if (config.testIdor) { count += payloads.IDOR_ID_REPLACEMENTS.length; }
  if (config.testIdorBody) { count += payloads.IDOR_BODY_VALUES.length * Math.max(1, 3); }
  if (config.testParamInject) { count += payloads.PARAM_INJECTION_PAYLOADS.length; }
  if (config.testSqlInject) { count += payloads.SQL_INJECTION_PAYLOADS.length; }
  if (config.testNoSqlInject) { count += 6 * payloads.NOSQL_INJECTION_PAYLOADS.length; }
  if (config.testSsrf) { count += 7 * payloads.SSRF_PAYLOADS.length; }
  if (config.testMassAssignment) { count += payloads.MASS_ASSIGNMENT_PAYLOADS.length; }
  if (config.testBusinessLogic) { count += payloads.BUSINESS_LOGIC_PAYLOADS.length; }
  if (config.testInterfaceAbuse) { count += 10 * payloads.INTERFACE_ABUSE_PAYLOADS.length; }
  if (config.testRaceCondition) { count += 1; }
  if (config.testSignBypass) { count += payloads.SIGN_BYPASS_HEADERS.length + payloads.SIGN_BYPASS_PARAMS.length; }
  return count || 1;
}
