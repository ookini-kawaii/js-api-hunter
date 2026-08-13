# 贡献指南

感谢你帮助改进 JS API Hunter。较大的扫描行为或界面变更，请先建立 Issue 说明目标、使用场景和兼容性影响。

## 本地开发

需要 Node.js 20 和兼容的 VS Code 版本。

```bash
npm ci
npm run compile
npm run bundle
```

提交前请确保 TypeScript 编译和扩展打包均成功。涉及端点解析、请求生成或 Fuzz 行为时，请使用本地靶场或明确授权的测试环境验证，不得对第三方系统发起测试。

## 变更要求

- 保持 PR 单一目的，说明行为变化和测试结果。
- 新增配置项或命令时同步更新 README 和 `package.json` 声明。
- 安全测试载荷应可解释、可控，不得携带真实凭证或目标数据。
- 依赖升级需兼顾 VS Code 扩展宿主的 Node.js 兼容性，不能只以审计数字作为升级依据。
