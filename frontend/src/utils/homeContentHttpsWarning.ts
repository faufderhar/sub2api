import { isHttpsAbsoluteUrl } from '@/utils/sanitize'

/**
 * F-2 / FD2-4 / FD2-8：判断后台「首页内容」是否会因非 https / 明显误填而无法按 URL 嵌入。
 * - URL 模式（trim 后以 http(s):// 开头）：非 https 绝对地址则提示
 * - 明显想填地址但格式不对：整段 trim 后是不含空白的单独 token，且像
 *   javascript: / data: / 残缺 http(s): / 协议相对 //（FD2-8 收紧，避免正文误报）
 * - 富文本模式：含 src 为非 https 的 iframe 则提示（与 sanitizeHomeContent 移除规则对齐）
 * 只提示不阻止保存。
 */

/** Printable ASCII excluding space — URL host/path/query material. */
const ASCII_URLISH = /^[\x21-\x7E]+$/

/**
 * FD2-8：整段内容是否像「单独填了一个地址」。
 * - trim 后不含空白、不含 `<`
 * - 以 `//` 或 `javascript:` / `data:` / 非 `://` 的 `http(s):` 开头
 * - scheme 后的其余部分须为可打印 ASCII（排除「http:说明文字」类正文）
 */
export function looksLikeMalformedHomeUrlToken(trimmed: string): boolean {
  if (!trimmed || /\s/.test(trimmed) || trimmed.includes('<')) return false

  if (trimmed.startsWith('//')) {
    return ASCII_URLISH.test(trimmed.slice(2)) || trimmed.length === 2
  }

  const m = /^(javascript|data|https?):(.*)$/i.exec(trimmed)
  if (!m) return false

  // Legitimate URL mode is handled by the http(s):// branch; not "malformed".
  if (/^https?:\/\//i.test(trimmed)) return false

  const rest = m[2]
  if (!rest) return true
  return ASCII_URLISH.test(rest)
}

export function shouldWarnHomeContentHttp(content: string): boolean {
  const trimmed = (content || '').trim()
  if (!trimmed) return false

  if (/^https?:\/\//i.test(trimmed)) {
    return !isHttpsAbsoluteUrl(trimmed)
  }

  if (looksLikeMalformedHomeUrlToken(trimmed)) {
    return true
  }

  // 富文本：粗检 iframe src。用 DOMParser 在浏览器/jsdom 下解析更稳。
  if (typeof DOMParser === 'undefined') {
    return /<iframe\b[^>]*\bsrc\s*=\s*["']?\s*http:/i.test(trimmed)
  }
  try {
    const doc = new DOMParser().parseFromString(trimmed, 'text/html')
    const iframes = doc.querySelectorAll('iframe')
    for (const iframe of iframes) {
      const src = iframe.getAttribute('src')
      // 没有 src / 空 src / 非 https → 会被首页清洗掉，给管理员提示
      if (!isHttpsAbsoluteUrl(src)) return true
    }
  } catch {
    return /<iframe\b[^>]*\bsrc\s*=\s*["']?\s*http:/i.test(trimmed)
  }
  return false
}
