/**
 * JS API Hunter - 核心类型定义
 */

/** JS 文件来源 */
export type JsSource = 'puppeteer' | 'wayback' | 'manual';

/** 风险等级 */
export type RiskLevel = 'high' | 'medium' | 'low' | 'info';

/** 扫描阶段 */
export type ScanPhase = 'idle' | 'collecting' | 'parsing' | 'assembling' | 'done';

/** 收集到的 JS 文件 */
export interface JsFile {
  url: string;
  content: string;
  source: JsSource;
  size: number;
}

/** 参数信息 */
export interface ParamInfo {
  name: string;
  type: string;
  required: boolean;
  defaultValue?: string;
}

/** 端点信息 */
export interface EndpointInfo {
  id: string;
  url: string;
  method: string;
  path: string;
  baseUrl: string;
  fullUrl: string;
  headers: Record<string, string>;
  parameters: ParamInfo[];
  sourceFile: string;
  riskLevel: RiskLevel;
  tags: string[];
}

/** 扫描进度 */
export interface ScanProgress {
  phase: ScanPhase;
  jsFilesFound: number;
  endpointsFound: number;
  message: string;
}

/** 扫描上下文（全局状态） */
export interface ScanContext {
  targetUrl: string;
  jsFiles: JsFile[];
  endpoints: EndpointInfo[];
  progress: ScanProgress;
  fuzzResults: FuzzResult[];
}

/** 测试类型 */
export type TestType = 'auth_bypass' | 'idor' | 'param_inject' | 'sql_inject' | 'ssrf' | 'horizontal';

/** 测试状态 */
export type TestStatus = 'pending' | 'running' | 'passed' | 'failed' | 'error';

/** 单次测试结果 */
export interface SingleTestResult {
  testType: TestType;
  status: TestStatus;
  description: string;
  requestInfo: string;
  responseStatus?: number;
  responseBody?: string;
  finding?: string;
}

/** 端点 Fuzz 结果 */
export interface FuzzResult {
  endpointId: string;
  endpoint: EndpointInfo;
  targetHost: string;
  tests: SingleTestResult[];
  overallVulnerable: boolean;
  vulnerabilityLevel: RiskLevel;
  timestamp: number;
}

/** Fuzz 配置 */
export interface FuzzConfig {
  concurrentRequests: number;
  timeout: number;
  subdomains: string[];
  testAuthBypass: boolean;
  testIdor: boolean;
  testParamInject: boolean;
  testSqlInject: boolean;
  testSsrf: boolean;
  testHorizontal: boolean;
}

/** Fuzz 进度 */
export interface FuzzProgress {
  phase: string;
  total: number;
  completed: number;
  message: string;
}
