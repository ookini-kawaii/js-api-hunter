/**
 * Fuzzer 模块功能测试
 * 注意：需要真实网络请求，仅验证模块加载和结构正确性
 */

const { runFuzz, runHorizontalFuzz } = require('../out/fuzzer/fuzzer.js');

const mockEndpoint = {
  id: 'test_1',
  url: '',
  method: 'GET',
  path: '/api/user/profile',
  baseUrl: '',
  fullUrl: 'https://httpbin.org/get',
  headers: {},
  parameters: [],
  sourceFile: 'test.js',
  riskLevel: 'medium',
  tags: ['user', 'api']
};

const mockConfig = {
  concurrentRequests: 5,
  timeout: 5000,
  subdomains: [],
  testAuthBypass: true,
  testIdor: false,
  testParamInject: false,
  testSqlInject: false,
  testSsrf: false,
  testHorizontal: false
};

async function testFuzzer() {
  console.log('\n=== Fuzzer 功能测试 ===\n');

  // 测试1: 模块加载
  console.log('[TEST] 模块加载...');
  if (typeof runFuzz !== 'function' || typeof runHorizontalFuzz !== 'function') {
    console.log('  FAIL: 函数导出异常');
    process.exit(1);
  }
  console.log('  PASS');

  // 测试2: 越权测试
  console.log('[TEST] 越权测试 (auth bypass)...');
  const result = await runFuzz(mockEndpoint, mockConfig, (progress) => {
    console.log(`  进度: ${progress.phase} - ${progress.message}`);
  });
  console.log(`  结果: ${result.tests.length} 项测试`);
  console.log(`  漏洞: ${result.tests.filter(t => t.status === 'failed').length}`);

  const checks = [];

  // 验证结果结构
  checks.push({
    name: '结果包含越权测试',
    pass: result.tests.some(t => t.testType === 'auth_bypass')
  });

  checks.push({
    name: '测试项正确计数',
    pass: result.tests.length > 0
  });

  checks.push({
    name: 'overallVulnerable 布尔类型',
    pass: typeof result.overallVulnerable === 'boolean'
  });

  checks.push({
    name: 'timestamp 有效',
    pass: result.timestamp > 0
  });

  for (const check of checks) {
    console.log(`  ${check.pass ? 'PASS' : 'FAIL'}: ${check.name}`);
  }

  const allPass = checks.every(c => c.pass);
  console.log(`\n${allPass ? '所有测试通过!' : '部分测试失败'}\n`);
  process.exit(allPass ? 0 : 1);
}

testFuzzer().catch(err => {
  console.error('测试异常:', err.message);
  process.exit(1);
});
