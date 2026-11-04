import DOMPurify from 'dompurify'

export function sanitizeSvg(svg: string): string {
  if (!svg) return ''
  return DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true, svgFilters: true } })
}

// 首页清洗专用的独立 DOMPurify 实例（D-3）：hook 只挂在这个实例上，
// 不影响其他地方直接使用的全局 DOMPurify（公告、支付说明、自定义页等）。
let homePurifier: ReturnType<typeof DOMPurify> | null = null

function getHomePurifier(): ReturnType<typeof DOMPurify> {
  if (homePurifier) return homePurifier
  const purifier = DOMPurify(window)
  purifier.addHook('afterSanitizeAttributes', (node) => {
    if (!(node instanceof Element)) return
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
 * - 与 CustomPageView 一致，允许 <iframe>（嵌入视频等），src 仍经过 DOMPurify 的 URL 校验，srcdoc 不放行。
 * - FORCE_BODY：自定义首页通常以 <style> 开头，不加这个选项时开头的 <style> 会被丢掉。
 * - 保留 <a target>，避免“新窗口打开”的链接行为发生变化；target="_blank" 时补上
 *   rel="noopener noreferrer"（D-3，保留原有的其他 rel 值）。
 * - 保留 iframe 的 sandbox、allow、referrerpolicy、loading（D-2）：管理员用 sandbox 收紧权限、
 *   常见嵌入代码用 allow 开启自动播放/全屏等，剥掉反而会放宽限制或造成功能回归。
 */
export function sanitizeHomeContent(html: string): string {
  if (!html) return ''
  return getHomePurifier().sanitize(html, {
    FORCE_BODY: true,
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allowfullscreen', 'frameborder', 'target', 'sandbox', 'allow', 'referrerpolicy', 'loading']
  })
}
