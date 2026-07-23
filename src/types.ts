/**
 * JS API Hunter - 核心类型定义
 */

/** JS 文件来源 */
export type JsSource = 'puppeteer' | 'wayback' | 'manual' | 'sourcemap';

/** 风险等级 */
export type RiskLevel = 'high' | 'medium' | 'low' | 'info';

/** 扫描阶段 */
export type ScanPhase = 'idle' | 'collecting' | 'parsing' | 'assembling' | 'fuzzing' | 'done';

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
  /** 该端点是否经过重放验证可达 */
  isReachable?: boolean;
  /** 验证请求返回的状态码 */
  verifyStatus?: number;
  /** 验证请求返回体长度 */
  verifyLength?: number;
}

/** 敏感信息发现 */
export interface SecretFinding {
  /** 类型：cloud_key / api_key / jwt / password / internal_domain / private_key / secret / token */
  type: string;
  /** 简短名称 */
  name: string;
  /** 原始值（已做掩码处理） */
  value: string;
  /** 来源 JS 文件 URL */
  sourceFile: string;
  /** 上下文片段 */
  snippet: string;
  /** 风险等级 */
  riskLevel: RiskLevel;
}

/** 子域名分类 */
export type SubdomainCategory = 'test' | 'legacy' | 'admin' | 'api' | 'internal' | 'other';

/** 子域名信息 */
export interface SubdomainInfo {
  /** 完整主机名，如 test.target.com */
  host: string;
  /** 解析到的 IP（可能为空） */
  ip?: string;
  /** HTTP 探测状态码 */
  httpStatus?: number;
  /** 是否存活 */
  isAlive: boolean;
  /** 备注：如 DNS 解析失败 / HTTP 超时 */
  note?: string;
  /** 子域名分类（按 PDF 出洞率优先级） */
  category?: SubdomainCategory;
  /** 子域名来源：prefix / crtsh / manual */
  source?: string;
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
  /** 发现的敏感信息 */
  secrets: SecretFinding[];
  /** 收集到的子域名 */
  subdomains: SubdomainInfo[];
  progress: ScanProgress;
  fuzzResults: FuzzResult[];
}

/** 测试类型 */
export type TestType =
  | 'auth_bypass'
  | 'idor'
  | 'idor_body'
  | 'param_inject'
  | 'sql_inject'
  | 'nosql_inject'
  | 'ssrf'
  | 'mass_assignment'
  | 'business_logic'
  | 'interface_abuse'
  | 'race_condition'
  | 'sign_bypass'
  | 'horizontal';

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
  /** 测试时使用的完整 URL（含路径变异等） */
  testUrl?: string;
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
  /** 用户提供的测试 Token，带/不带 Token 两个版本都会测 */
  userToken?: string;
  /** 第二个账号 Token，用于 IDOR 两账号对比 */
  comparisonToken?: string;
  testAuthBypass: boolean;
  testIdor: boolean;
  testIdorBody: boolean;
  testParamInject: boolean;
  testSqlInject: boolean;
  testNoSqlInject: boolean;
  testSsrf: boolean;
  testMassAssignment: boolean;
  testBusinessLogic: boolean;
  testInterfaceAbuse: boolean;
  testRaceCondition: boolean;
  testSignBypass: boolean;
  /** 横向 Fuzz 时是否启用路径变异 */
  pathVariants: boolean;
  testHorizontal: boolean;
}

/** Fuzz 进度 */
export interface FuzzProgress {
  phase: string;
  total: number;
  completed: number;
  message: string;
}

/** 报告格式 */
export type ReportFormat = 'json' | 'markdown' | 'html' | 'csv' | 'src';
