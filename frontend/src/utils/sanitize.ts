import DOMPurify from 'dompurify'

export function sanitizeSvg(svg: string): string {
  if (!svg) return ''
  return DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true, svgFilters: true } })
}

/**
 * 判断是否为 https 绝对地址。不带 base 解析：相对地址、协议相对地址 //host 会解析失败；
 * 大小写、首尾空白、制表/换行混淆等由 URL 解析按浏览器同样的规则归一后再看协议。
 */
export function isHttpsAbsoluteUrl(value: string | null | undefined): boolean {
  if (!value || !value.trim()) return false
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && url.hostname !== ''
  } catch {
    return false
  }
}

/** 首页 iframe 默认 sandbox 权限（F-1）。同源 token 只作用于被嵌页面自身的源，不影响本站。 */
export const HOME_IFRAME_SANDBOX_DEFAULT = [
  'allow-scripts',
  'allow-same-origin',
  'allow-popups',
  'allow-forms'
] as const

/**
 * A-1：iframe src 与本站同源时，默认与自定义 sandbox 都不能带 allow-same-origin。
 * 用 new URL(src, location.href) 解析；相对路径算同源。无法解析时按跨域处理（保留默认集合）。
 */
export function isHomeIframeSameOrigin(
  src: string | null | undefined,
  baseHref: string = typeof window !== 'undefined' ? window.location.href : 'http://localhost/',
  pageOrigin: string = typeof window !== 'undefined' ? window.location.origin : 'http://localhost'
): boolean {
  if (!src || !String(src).trim()) return false
  try {
    const resolved = new URL(String(src).trim(), baseHref)
    return resolved.origin === pageOrigin
  } catch {
    return false
  }
}

/**
 * 计算 iframe 最终 sandbox：与默认 token 取交集，不放宽。
 * - 未写 sandbox → 用默认全集（同源时去掉 allow-same-origin，A-1）
 * - 写了 sandbox（含空字符串）→ 只保留默认集合内的 token；同源时仍去掉 allow-same-origin
 * 空属性表示最严（无权限），交集仍为空。
 * 大小写 / 多余空白在 token 归一化时处理。
 */
export function resolveHomeIframeSandbox(
  existing: string | null | undefined,
  src?: string | null
): string {
  const sameOrigin = isHomeIframeSameOrigin(src)
  const allowed: string[] = sameOrigin
    ? HOME_IFRAME_SANDBOX_DEFAULT.filter((t) => t !== 'allow-same-origin')
    : [...HOME_IFRAME_SANDBOX_DEFAULT]
  const allowedSet = new Set<string>(allowed)

  if (existing === null || existing === undefined) {
    return allowed.join(' ')
  }
  const tokens = existing
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .filter((t) => allowedSet.has(t))
  // 稳定顺序：按默认 token 顺序输出（同源时已不含 allow-same-origin）
  return allowed.filter((t) => tokens.includes(t)).join(' ')
}


// 首页清洗专用的独立 DOMPurify 实例（D-3）：hook 只挂在这个实例上，
// 不影响其他地方直接使用的全局 DOMPurify（公告、支付说明、自定义页等）。
let homePurifier: ReturnType<typeof DOMPurify> | null = null

function getHomePurifier(): ReturnType<typeof DOMPurify> {
  if (homePurifier) return homePurifier
  const purifier = DOMPurify(window)
  purifier.addHook('afterSanitizeAttributes', (node) => {
    if (!(node instanceof Element)) return
    // 首页富文本里的 iframe 只允许 https 绝对地址：src 缺失/为空/解析失败/非 https 的 iframe 整个移除。
    // 在 DOMPurify 处理完属性后判断（javascript: 等此时已被剥掉 src），用 URL 解析而不是前缀匹配。
    if (node.nodeName.toLowerCase() === 'iframe') {
      if (!isHttpsAbsoluteUrl(node.getAttribute('src'))) {
        node.remove()
        return
      }
      // F-1 / A-1：统一加 sandbox；管理员自写的取交集，不放宽；同源去掉 allow-same-origin
      const hadSandbox = node.hasAttribute('sandbox')
      const src = node.getAttribute('src')
      node.setAttribute(
        'sandbox',
        resolveHomeIframeSandbox(hadSandbox ? node.getAttribute('sandbox') : null, src)
      )
    }
    if ((node.getAttribute('target') || '').trim().toLowerCase() !== '_blank') return
    const rel = new Set((node.getAttribute('rel') || '').toLowerCase().split(/\s+/).filter(Boolean))
    rel.add('noopener')
    rel.add('noreferrer')
    node.setAttribute('rel', [...rel].join(' '))
  })
  homePurifier = purifier
  return purifier
}

/**
 * 清洗管理员配置的首页自定义 HTML（home_content，HomeView 用 v-html 渲染）。L-1
 *
 * - 去掉 <script>、on* 事件属性、javascript: 等危险 URL（DOMPurify 默认行为）。
 * - 保留常规排版：标签、class、内联 style、<style>、图片、链接等。
 * - 允许 <iframe>（嵌入视频等），但只保留 src 为 https 绝对地址的 iframe，其余整个移除；srcdoc 不放行。
 * - FORCE_BODY：自定义首页通常以 <style> 开头，不加这个选项时开头的 <style> 会被丢掉。
 * - 保留 <a target>，避免“新窗口打开”的链接行为发生变化；target="_blank" 时补上
 *   rel="noopener noreferrer"（D-3，保留原有的其他 rel 值）。
 * - 保留 iframe 的 sandbox、allow、referrerpolicy、loading（D-2）：管理员用 sandbox 收紧权限、
 *   常见嵌入代码用 allow 开启自动播放/全屏等，剥掉反而会放宽限制或造成功能回归。
 * - F-1 / A-1：所有保留的 iframe 统一写入 sandbox；默认 allow-scripts allow-same-origin
 *   allow-popups allow-forms；管理员自写的 sandbox 与默认取交集，不放宽。
 *   同源 iframe（含相对路径）默认与自定义都不能带 allow-same-origin。
 */
export function sanitizeHomeContent(html: string): string {
  if (!html) return ''
  return getHomePurifier().sanitize(html, {
    FORCE_BODY: true,
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allowfullscreen', 'frameborder', 'target', 'sandbox', 'allow', 'referrerpolicy', 'loading']
  })
}
