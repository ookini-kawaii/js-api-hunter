/**
 * SignAnalyzer - 签名/加密逻辑分析器
 * 从 JS 文件中识别 sign/encrypt/md5 等逻辑，生成 Console 调用模板
 */

import { JsFile } from '../types';

export interface SignPattern {
  type: 'signature' | 'encryption' | 'hashing' | 'token';
  name: string;
  functionName: string;
  snippet: string;
  consoleTemplate: string;
  sourceFile: string;
}

/** 分析所有 JS 文件中的签名/加密逻辑 */
export function analyzeSignatures(jsFiles: JsFile[]): SignPattern[] {
  const patterns: SignPattern[] = [];
  const seen = new Set<string>();

  for (const file of jsFiles) {
    const found = scanFile(file);
    for (const p of found) {
      const key = `${p.type}:${p.functionName}:${file.url}`;
      if (!seen.has(key)) {
        seen.add(key);
        patterns.push(p);
      }
    }
  }

  return patterns;
}

function scanFile(file: JsFile): SignPattern[] {
  const patterns: SignPattern[] = [];
  const content = file.content;

  // 1. 搜索签名函数
  patterns.push(...findSignatureFunctions(content, file));

  // 2. 搜索加密调用
  patterns.push(...findEncryptionCalls(content, file));

  // 3. 搜索哈希函数
  patterns.push(...findHashingCalls(content, file));

  // 4. 搜索 Token/认证生成
  patterns.push(...findTokenGeneration(content, file));

  return patterns;
}

/** 搜索签名函数 */
function findSignatureFunctions(content: string, file: JsFile): SignPattern[] {
  const patterns: SignPattern[] = [];

  // 函数定义: function sign(, function getSign(, const sign = (
  const signFuncRegex = /(?:function|const|let|var)\s+(\w*sign\w*)\s*(?:[:=]\s*(?:function\s*)?)?\(([^)]*)\)\s*\{([^}]{0,300})\}/gi;
  let match: RegExpExecArray | null;

  while ((match = signFuncRegex.exec(content)) !== null) {
    const funcName = match[1];
    const params = match[2];
    const body = match[3].slice(0, 200);

    patterns.push({
      type: 'signature',
      name: `签名函数: ${funcName}`,
      functionName: funcName,
      snippet: `function ${funcName}(${params}) { ${body}... }`,
      consoleTemplate: `// 在浏览器 Console 中调用:\n// const result = ${funcName}(yourParams);\n// console.log(result);`,
      sourceFile: file.url
    });
  }

  // 箭头函数: const sign = (params) => {
  const arrowSignRegex = /(?:const|let|var)\s+(\w*sign\w*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{/gi;
  while ((match = arrowSignRegex.exec(content)) !== null) {
    const funcName = match[1];
    const params = match[2];

    if (!patterns.some(p => p.functionName === funcName)) {
      patterns.push({
        type: 'signature',
        name: `签名函数(箭头): ${funcName}`,
        functionName: funcName,
        snippet: `const ${funcName} = (${params}) => { ... }`,
        consoleTemplate: `// 在浏览器 Console 中调用:\n// const result = ${funcName}(yourParams);\n// console.log(result);`,
        sourceFile: file.url
      });
    }
  }

  // axios interceptor 中的签名
  const interceptorRegex = /(?:request|interceptors)\s*\.\s*use\s*\(\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{([^}]{0,500})\}/gi;
  while ((match = interceptorRegex.exec(content)) !== null) {
    const body = match[2].toLowerCase();
    if (body.includes('sign') || body.includes('md5') || body.includes('encrypt') || body.includes('token')) {
      patterns.push({
        type: 'signature',
        name: '请求拦截器签名',
        functionName: 'interceptor',
        snippet: `interceptor: ${match[2].slice(0, 200).trim()}...`,
        consoleTemplate: '// 签名逻辑在 axios 请求拦截器中，无法直接调用\n// 建议: 在 Burp Repeater 中使用已有 Token 重放',
        sourceFile: file.url
      });
    }
  }

  return patterns;
}

/** 搜索加密调用 */
function findEncryptionCalls(content: string, file: JsFile): SignPattern[] {
  const patterns: SignPattern[] = [];

  const encryptPatterns = [
    { regex: /(\w+\.encrypt\s*\([^)]+\))/gi, type: 'encryption' as const, desc: '加密调用' },
    { regex: /(\w+\.decrypt\s*\([^)]+\))/gi, type: 'encryption' as const, desc: '解密调用' },
    { regex: /(crypto\.\w+\([^)]+\))/gi, type: 'encryption' as const, desc: 'Web Crypto' },
    { regex: /(btoa\s*\([^)]+\))/gi, type: 'encryption' as const, desc: 'Base64 编码' },
    { regex: /(atob\s*\([^)]+\))/gi, type: 'encryption' as const, desc: 'Base64 解码' },
    { regex: /(CryptoJS\.\w+\([^)]+\))/gi, type: 'encryption' as const, desc: 'CryptoJS' },
    { regex: /(\.setSignature\s*\([^)]*\))/gi, type: 'signature' as const, desc: 'setSignature' },
  ];

  for (const { regex, type, desc } of encryptPatterns) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const snippet = match[1];
      if (snippet.length < 200) {
        patterns.push({
          type,
          name: desc,
          functionName: snippet.split('(')[0],
          snippet,
          consoleTemplate: `// 在 Console 中执行:\n// ${snippet}`,
          sourceFile: file.url
        });
      }
    }
  }

  return patterns;
}

/** 搜索哈希函数 */
function findHashingCalls(content: string, file: JsFile): SignPattern[] {
  const patterns: SignPattern[] = [];

  const hashPatterns = [
    { regex: /(\w+\.MD5\s*\([^)]*\))/gi, desc: 'MD5 调用' },
    { regex: /(\w+\.SHA\d*\s*\([^)]*\))/gi, desc: 'SHA 调用' },
    { regex: /(\w+\.hmac\w*\s*\([^)]*\))/gi, desc: 'HMAC 调用' },
    { regex: /(\w+\.createHash\s*\([^)]*\))/gi, desc: 'createHash 调用' },
    { regex: /(md5\s*\([^)]*\))/gi, desc: 'md5()' },
    { regex: /(sha\w*\s*\([^)]*\))/gi, desc: 'sha()' },
    { regex: /(hex_md5\s*\([^)]*\))/gi, desc: 'hex_md5()' },
  ];

  for (const { regex, desc } of hashPatterns) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const snippet = match[1];
      if (snippet.length < 200) {
        patterns.push({
          type: 'hashing',
          name: desc,
          functionName: snippet.split('(')[0],
          snippet,
          consoleTemplate: `// 在 Console 中执行:\n// ${snippet}`,
          sourceFile: file.url
        });
      }
    }
  }

  return patterns;
}

/** 搜索 Token 生成 */
function findTokenGeneration(content: string, file: JsFile): SignPattern[] {
  const patterns: SignPattern[] = [];

  // Token 生成模式
  const tokenPatterns = [
    /(?:token|jwt|auth)\s*[:=]\s*["'`]([^"'`]{20,})["'`]/gi,
    /(?:generateToken|createToken|getToken|refreshToken)\s*\([^)]*\)/gi,
    /(?:access_token|accessToken|api_key|apiKey|secret_key|secretKey)\s*[:=]\s*["'`]([^"'`]{10,})["'`]/gi,
  ];

  for (const regex of tokenPatterns) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const snippet = match[0];
      if (snippet.length < 300) {
        patterns.push({
          type: 'token',
          name: 'Token 生成/配置',
          functionName: snippet.split(/[:=(]/)[0].trim(),
          snippet,
          consoleTemplate: '// 检测到 Token 相关配置，可能是硬编码凭证！',
          sourceFile: file.url
        });
      }
    }
  }

  return patterns;
}

/** 生成 Console 调用脚本 */
export function generateConsoleScript(patterns: SignPattern[]): string {
  if (patterns.length === 0) {
    return '// 未检测到签名/加密逻辑';
  }

  let script = '// ===== JS API Hunter - 签名分析结果 =====\n';
  script += `// 发现 ${patterns.length} 个签名/加密相关逻辑\n\n`;

  for (const p of patterns) {
    script += `// --- [${p.type.toUpperCase()}] ${p.name} ---\n`;
    script += `// 来源: ${p.sourceFile}\n`;
    script += `${p.consoleTemplate}\n\n`;
  }

  script += '// ===== 使用建议 =====\n';
  script += '// 1. 在目标网站打开 DevTools Console\n';
  script += '// 2. 复制上面的函数调用，替换参数\n';
  script += '// 3. 将返回的签名值填入 Burp Repeater 的请求中\n';

  return script;
}
