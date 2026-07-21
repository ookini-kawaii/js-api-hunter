const { analyzeSignatures, generateConsoleScript } = require('../out/signer/signer.js');

const sampleJs = [{
  url: 'app.js',
  content: `
    function sign(params, secret) {
      return md5(params + secret + timestamp);
    }

    const encryptData = (data) => {
      return btoa(JSON.stringify(data));
    };

    api.interceptors.request.use(async (config) => {
      config.headers['X-Sign'] = sign(config.data, 'mySecretKey');
      config.headers['X-Token'] = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
      return config;
    });

    const hash = CryptoJS.MD5(JSON.stringify(body));
    const token = createToken(user);
  `,
  source: 'test',
  size: 300
}];

const patterns = analyzeSignatures(sampleJs);
const script = generateConsoleScript(patterns);

console.log(`\n=== 签名分析 (${patterns.length} 个模式) ===\n`);
for (const p of patterns) {
  console.log(`[${p.type.toUpperCase()}] ${p.name}`);
  console.log(`  func: ${p.functionName}`);
  console.log(`  snippet: ${p.snippet.slice(0, 80)}`);
  console.log();
}

console.log('=== Console 脚本 ===\n');
console.log(script);

// Validate
const checks = [
  { name: '签到名函数', pass: patterns.some(p => p.functionName === 'sign' && p.type === 'signature') },
  { name: '加密调用 btoa', pass: patterns.some(p => p.snippet.includes('btoa')) },
  { name: 'CryptoJS 检测', pass: patterns.some(p => p.snippet.includes('CryptoJS')) },
  { name: '拦截器检测', pass: patterns.some(p => p.name === '请求拦截器签名') },
  { name: 'Token 检测', pass: patterns.some(p => p.type === 'token') },
];

console.log('\n=== 验证 ===');
let allPass = true;
for (const check of checks) {
  const status = check.pass ? 'PASS' : 'FAIL';
  console.log(`  ${status}  ${check.name}`);
  if (!check.pass) { allPass = false; }
}
console.log(`\n${allPass ? '全部通过!' : '部分失败'}\n`);
process.exit(allPass ? 0 : 1);
