const fs = require('fs');
const { runFuzz } = require('../out/fuzzer/fuzzer.js');

const ep = {
  id: 't',
  url: '',
  method: 'GET',
  path: '/get',
  baseUrl: '',
  fullUrl: 'https://httpbin.org/get',
  headers: {},
  parameters: [],
  sourceFile: 't.js',
  riskLevel: 'low',
  tags: []
};

const config = {
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

async function main() {
  const result = await runFuzz(ep, config, (p) => {
    console.log(`  [${p.phase}] ${p.message}`);
  });

  const summary = {
    tests: result.tests.length,
    vulnerable: result.tests.filter(t => t.status === 'failed').length,
    passed: result.tests.filter(t => t.status === 'passed').length,
    errors: result.tests.filter(t => t.status === 'error').length,
    overallVulnerable: result.overallVulnerable,
    vulnLevel: result.vulnerabilityLevel
  };

  console.log('\n=== 结果 ===');
  console.log(JSON.stringify(summary, null, 2));

  console.log('\n=== 测试详情 ===');
  for (const t of result.tests) {
    console.log(`  [${t.status}] ${t.description} → resp=${t.responseStatus}`);
    if (t.finding) {
      console.log(`    FINDING: ${t.finding}`);
    }
  }
}

main().catch(e => console.error(e));
