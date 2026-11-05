import { isHttpsAbsoluteUrl } from '@/utils/sanitize'

/**
 * F-2：判断后台「首页内容」是否会因非 https 而无法显示。
 * - URL 模式（trim 后以 http(s):// 开头，协议大小写不敏感）：非 https 绝对地址则提示
 * - 富文本模式：含 src 为非 https 的 iframe 则提示（与 sanitizeHomeContent 移除规则对齐）
 * 只提示不阻止保存。
 */
export function shouldWarnHomeContentHttp(content: string): boolean {
  const trimmed = (content || '').trim()
  if (!trimmed) return false

  if (/^https?:\/\//i.test(trimmed)) {
    return !isHttpsAbsoluteUrl(trimmed)
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
