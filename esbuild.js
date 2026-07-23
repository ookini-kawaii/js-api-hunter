const esbuild = require('esbuild');

// Bundle extension entry point (vscode is external)
esbuild.buildSync({
  entryPoints: ['./out/extension.js'],
  bundle: true,
  outfile: './dist/extension.js',
  external: ['vscode'],
  format: 'cjs',
  platform: 'node',
  minify: true,
  sourcemap: false,
});

// Bundle MCP server entry point
esbuild.buildSync({
  entryPoints: ['./out/mcp/server.js'],
  bundle: true,
  outfile: './dist/mcp/server.js',
  format: 'cjs',
  platform: 'node',
  minify: true,
  sourcemap: false,
});

console.log('Bundled extension and MCP server to ./dist');
