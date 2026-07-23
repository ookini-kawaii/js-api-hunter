/**
 * Source Map 发现与源码还原
 * 对应 PDF 第 4 章：检查 source map，用 unwebpack-sourcemap 还原源码
 */

import { JsFile } from '../types';

interface SourceMap {
  version: number;
  sources?: string[];
  sourcesContent?: string[];
  file?: string;
}

/**
 * 为已收集的 JS 文件自动发现 .map 文件并还原源码
 */
export async function discoverSourceMaps(
  jsFiles: JsFile[],
  onProgress?: (found: number) => void
): Promise<JsFile[]> {
  const results: JsFile[] = [];
  const checked = new Set<string>();

  for (const js of jsFiles) {
    if (!js.url.endsWith('.js')) { continue; }
    if (checked.has(js.url)) { continue; }
    checked.add(js.url);

    // 先尝试在 JS 文件末尾找 sourceMappingURL 注释
    const mapUrlFromComment = extractSourceMappingURL(js.content, js.url);
    const mapUrls = new Set<string>();
    if (mapUrlFromComment) { mapUrls.add(mapUrlFromComment); }
    mapUrls.add(js.url + '.map');

    for (const mapUrl of mapUrls) {
      try {
        const mapFile = await fetchSourceMap(mapUrl);
        if (!mapFile) { continue; }

        const restored = restoreFromSourceMap(mapFile, mapUrl, js.url);
        for (const f of restored) {
          results.push(f);
          if (onProgress) { onProgress(results.length); }
        }
      } catch {
        // 忽略失败
      }
    }
  }

  return results;
}

/** 从 JS 内容中提取 sourceMappingURL */
function extractSourceMappingURL(content: string, jsUrl: string): string | null {
  const match = content.match(/sourceMappingURL\s*=\s*([^\s]+)/);
  if (!match) { return null; }

  let url = match[1].trim();
  if (url.startsWith('http')) { return url; }

  // 相对路径转绝对路径
  const base = new URL(jsUrl);
  if (url.startsWith('/')) {
    return base.origin + url;
  }
  return base.href.substring(0, base.href.lastIndexOf('/') + 1) + url;
}

/** 下载 source map 文件 */
async function fetchSourceMap(mapUrl: string): Promise<SourceMap | null> {
  const resp = await fetch(mapUrl, {
    headers: { 'User-Agent': 'Mozilla/5.0' },
    signal: AbortSignal.timeout(15000)
  });

  if (!resp.ok) { return null; }
  const text = await resp.text();
  try {
    const json = JSON.parse(text) as SourceMap;
    return json && json.version ? json : null;
  } catch {
    return null;
  }
}

/** 从 source map 还原 JS 文件 */
function restoreFromSourceMap(
  map: SourceMap,
  mapUrl: string,
  originalJsUrl: string
): JsFile[] {
  const results: JsFile[] = [];
  const sources = map.sources || [];
  const contents = map.sourcesContent || [];

  if (contents.length === 0) {
    // 没有 sourcesContent，只生成一个占位文件
    results.push({
      url: mapUrl + '#metadata',
      content: `// Source map 不含 sourcesContent，无法还原源码\n// sources: ${sources.join(', ')}`,
      source: 'sourcemap',
      size: 0
    });
    return results;
  }

  for (let i = 0; i < sources.length; i++) {
    const content = contents[i];
    if (!content || content.length < 10) { continue; }

    const sourcePath = sources[i] || `source_${i}`;
    const pseudoUrl = `${originalJsUrl}#sourcemap/${sourcePath}`;

    results.push({
      url: pseudoUrl,
      content,
      source: 'sourcemap',
      size: content.length
    });
  }

  return results;
}
