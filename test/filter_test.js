/**
 * filterEndpoints 功能测试
 * 测试：去重、静态资源过滤、API 分类、额外关键词、禁用过滤
 */
const { filterEndpoints, DEFAULT_FILTER_CONFIG } = require('../out/parser/parser.js');

function ep(path, method = 'GET') {
  return {
    id: `${method}_${path}_1`,
    url: '',
    method,
    path,
    baseUrl: '',
    fullUrl: path,
    headers: {},
    parameters: [],
    sourceFile: 'test.js',
    riskLevel: 'low',
    tags: []
  };
}

function runTest(name, fn) {
  try {
    const pass = fn();
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}`);
    return pass;
  } catch (err) {
    console.log(`  ERROR  ${name}: ${err.message}`);
    return false;
  }
}

let allPass = true;

console.log('\n=== filterEndpoints 功能测试 ===\n');

// ========== 1. 去重测试 ==========
console.log('[1] 去重');
allPass &= runTest('相同 method+path 去重', () => {
  const input = [ep('/api/users'), ep('/api/users'), ep('/api/users')];
  const { kept, filtered } = filterEndpoints(input, DEFAULT_FILTER_CONFIG);
  return kept.length === 1;
});

allPass &= runTest('不同 method 不去重', () => {
  const input = [ep('/api/users', 'GET'), ep('/api/users', 'POST')];
  const { kept } = filterEndpoints(input, DEFAULT_FILTER_CONFIG);
  return kept.length === 2;
});

// ========== 2. 静态资源过滤 ==========
console.log('[2] 静态资源过滤');
const staticPaths = [
  '/assets/main.js', '/static/style.css', '/images/logo.png',
  '/fonts/icon.woff2', '/css/theme.css', '/img/bg.jpg',
  '/node_modules/react/index.js', '/dist/bundle.js',
  '/vendor/moment.min.js', '/favicon.ico', '/robots.txt',
  '/manifest.json', '/sitemap.xml', '/logo.svg'
];

for (const p of staticPaths) {
  allPass &= runTest(`静态资源被过滤: ${p}`, () => {
    const { kept, filtered } = filterEndpoints([ep(p)], DEFAULT_FILTER_CONFIG);
    return kept.length === 0 && filtered.length === 1;
  });
}

// ========== 3. API 端点保留 ==========
console.log('[3] API 端点保留');
const apiPaths = [
  '/api/users', '/v1/orders', '/rest/data', '/graphql',
  '/login', '/logout', '/admin/dashboard', '/user/profile',
  '/auth/token', '/webhook/callback', '/health/check',
  '/upload/file', '/search/query', '/order/pay',
  '/config/settings', '/data/stats'
];

for (const p of apiPaths) {
  allPass &= runTest(`API 端点保留: ${p}`, () => {
    const { kept, filtered } = filterEndpoints([ep(p)], DEFAULT_FILTER_CONFIG);
    return kept.length === 1 && filtered.length === 0;
  });
}

// ========== 4. 混合场景 ==========
console.log('[4] 混合场景');
allPass &= runTest('API + 静态资源混合过滤', () => {
  const input = [
    ep('/api/users'),
    ep('/api/orders'),
    ep('/assets/app.js'),
    ep('/images/logo.png'),
    ep('/css/style.css'),
    ep('/login'),
    ep('/public/page.html'),
    ep('/favicon.ico'),
  ];
  const { kept, filtered } = filterEndpoints(input, DEFAULT_FILTER_CONFIG);
  // /api/users, /api/orders, /login 应该保留
  // 其余应该过滤
  return kept.length === 3 && filtered.length === 5;
});

allPass &= runTest('既有重复又有静态资源', () => {
  const input = [
    ep('/api/users'),
    ep('/api/users'),        // 重复
    ep('/assets/app.js'),    // 静态
    ep('/images/logo.png'),  // 静态
    ep('/api/orders'),
    ep('/api/orders'),       // 重复
    ep('/css/main.css'),     // 静态
    ep('/login'),
  ];
  const { kept, filtered } = filterEndpoints(input, DEFAULT_FILTER_CONFIG);
  // 去重后: /api/users, /assets/app.js, /images/logo.png, /api/orders, /css/main.css, /login
  // 过滤后保留: /api/users, /api/orders, /login
  return kept.length === 3 && filtered.length === 3;
});

// ========== 5. 额外关键词 ==========
console.log('[5] 额外关键词');
allPass &= runTest('extraKeepKeywords 保留指定路径', () => {
  const config = {
    ...DEFAULT_FILTER_CONFIG,
    extraKeepKeywords: ['custom-endpoint']
  };
  const { kept } = filterEndpoints([ep('/assets/custom-endpoint/data')], config);
  return kept.length === 1;
});

allPass &= runTest('extraExcludeKeywords 排除指定路径', () => {
  const config = {
    ...DEFAULT_FILTER_CONFIG,
    extraExcludeKeywords: ['internal-debug']
  };
  const { kept } = filterEndpoints([ep('/api/internal-debug/secret')], config);
  return kept.length === 0;
});

// ========== 6. 禁用过滤 ==========
console.log('[6] 禁用过滤');
allPass &= runTest('enabled=false 时不过滤任何端点', () => {
  const input = [
    ep('/api/users'),
    ep('/assets/app.js'),
    ep('/images/logo.png'),
    ep('/css/style.css'),
  ];
  const { kept, filtered } = filterEndpoints(input, { ...DEFAULT_FILTER_CONFIG, enabled: false });
  return kept.length === 4 && filtered.length === 0;
});

// ========== 7. 空输入 ==========
console.log('[7] 边界条件');
allPass &= runTest('空端点列表', () => {
  const { kept, filtered } = filterEndpoints([], DEFAULT_FILTER_CONFIG);
  return kept.length === 0 && filtered.length === 0;
});

allPass &= runTest('单端点 API', () => {
  const { kept, filtered } = filterEndpoints([ep('/api/v1/users')], DEFAULT_FILTER_CONFIG);
  return kept.length === 1 && filtered.length === 0;
});

// ========== 8. endpointCategory 被正确设置 ==========
console.log('[8] endpointCategory 分类');
allPass &= runTest('API 端点标记为 api', () => {
  const { kept } = filterEndpoints([ep('/api/users')], DEFAULT_FILTER_CONFIG);
  return kept.length === 1 && kept[0].endpointCategory === 'api';
});

allPass &= runTest('静态资源标记为 static', () => {
  const { filtered } = filterEndpoints([ep('/assets/bundle.js')], DEFAULT_FILTER_CONFIG);
  return filtered.length === 1 && filtered[0].endpointCategory === 'static';
});

// ========== 结果 ==========
console.log(`\n${allPass ? '=== 全部通过! ===' : '=== 部分失败 ==='}`);
process.exit(allPass ? 0 : 1);
