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

/**
 * 首页 iframe 默认 sandbox 权限（F-1 / R3-IFRAME）。
 * 不含 allow-same-origin：跨源 iframe 导航/重定向回本站后也不能取得本站 origin 权限。
 * 去掉该 token 后，被嵌文档是不透明唯一源，无法读父页面 DOM/cookie/storage，也无法自行去掉 sandbox。
 * 依赖被嵌站点自身 cookie/storage 的第三方嵌入可能会受影响（见交付说明兼容清单）。
 */
export const HOME_IFRAME_SANDBOX_DEFAULT = [
  'allow-scripts',
  'allow-popups',
  'allow-forms'
] as const

/**
 * iframe src 是否与本站同源。用 new URL(src, location.href) 解析；相对路径算同源。
 * 无法解析时返回 false。R3-IFRAME 后 sandbox 计算不再依赖此结果，保留供测试与诊断。
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
 * - 未写 sandbox → 用默认全集（从不含 allow-same-origin，R3-IFRAME）
 * - 写了 sandbox（含空字符串）→ 只保留默认集合内的 token；allow-same-origin 一律丢掉
 * 空属性表示最严（无权限），交集仍为空。
 * 大小写 / 多余空白在 token 归一化时处理。
 * `src` 保留以兼容调用方；不再根据初始 src 决定是否去掉 allow-same-origin
 * （跨源导航回本站后读 location 也不可靠）。
 */
export function resolveHomeIframeSandbox(
  existing: string | null | undefined,
  _src?: string | null
): string {
  const allowed = [...HOME_IFRAME_SANDBOX_DEFAULT]
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
  // 稳定顺序：按默认 token 顺序输出（已不含 allow-same-origin）
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
      // F-1 / A-1 / R3-IFRAME：统一加 sandbox；管理员自写的取交集，不放宽；永不写 allow-same-origin
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
 * - F-1 / A-1 / R3-IFRAME：所有保留的 iframe 统一写入 sandbox；默认 allow-scripts
 *   allow-popups allow-forms；管理员自写的 sandbox 与默认取交集，不放宽。
 *   默认与自定义都不能带 allow-same-origin（不依赖初始 src 是否同源）。
 */
export function sanitizeHomeContent(html: string): string {
  if (!html) return ''
  return getHomePurifier().sanitize(html, {
    FORCE_BODY: true,
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allowfullscreen', 'frameborder', 'target', 'sandbox', 'allow', 'referrerpolicy', 'loading']
  })
}
