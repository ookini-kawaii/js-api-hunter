const { parseEndpoints } = require('../out/parser/parser.js');

const sampleJs = [
  {
    url: 'app.js',
    content: `
const api = axios.create({ baseURL: 'https://api.target.com/v1' });
api.get('/user/profile');
api.post('/order/create');
fetch('/api/admin/users');
fetch('/api/config', { method: 'DELETE' });
router.delete('/user/123');
$.ajax({ url: '/api/health' });
const xhr = new XMLHttpRequest();
xhr.open('PUT', '/api/settings');
VUE_APP_API_URL = 'https://vue-api.target.com';
`,
    source: 'test',
    size: 200
  },
  {
    url: 'vendor.js',
    content: `
baseURL: 'https://legacy.target.com/api',
this.apiUrl = 'https://internal.target.com/v2';
api.patch('/user/update-email');
fetch('/public/news');
fetch('/graphql');
const secretPath = '/admin/backup/database';
`,
    source: 'test',
    size: 150
  }
];

const endpoints = parseEndpoints(sampleJs);

console.log(`\n=== 发现的端点 (${endpoints.length} 个) ===\n`);
endpoints.forEach(ep => {
  console.log(`[${ep.riskLevel.toUpperCase().padEnd(6)}] ${ep.method.padEnd(6)} ${ep.path.padEnd(30)} | tags: ${ep.tags.join(', ')}`);
});

// 验证结果
console.log('\n=== 验证 ===');
const checks = [
  { name: 'admin endpoints marked HIGH', pass: endpoints.filter(e => e.path.includes('/admin')).every(e => e.riskLevel === 'high') },
  { name: 'methods detected correctly', pass: endpoints.some(e => e.method === 'DELETE') && endpoints.some(e => e.method === 'POST') },
  { name: 'graphql tagged', pass: endpoints.some(e => e.tags.includes('graphql')) },
  { name: 'risk levels sorted (high first)', pass: endpoints.length > 0 && endpoints[0].riskLevel === 'high' }
];

let allPass = true;
for (const check of checks) {
  const status = check.pass ? 'PASS' : 'FAIL';
  console.log(`  ${status}  ${check.name}`);
  if (!check.pass) allPass = false;
}

console.log(`\n${allPass ? '全部通过!' : '部分测试失败'}\n`);
process.exit(allPass ? 0 : 1);
