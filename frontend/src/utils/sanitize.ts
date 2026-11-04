import DOMPurify from 'dompurify'

export function sanitizeSvg(svg: string): string {
  if (!svg) return ''
  return DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true, svgFilters: true } })
}

/**
 * 清洗管理员配置的首页自定义 HTML（home_content，HomeView 用 v-html 渲染）。L-1
 *
 * - 去掉 <script>、on* 事件属性、javascript: 等危险 URL（DOMPurify 默认行为）。
 * - 保留常规排版：标签、class、内联 style、<style>、图片、链接等。
 * - 与 CustomPageView 一致，允许 <iframe>（嵌入视频等），src 仍经过 DOMPurify 的 URL 校验，srcdoc 不放行。
 * - FORCE_BODY：自定义首页通常以 <style> 开头，不加这个选项时开头的 <style> 会被丢掉。
 * - 保留 <a target>，避免“新窗口打开”的链接行为发生变化。
 */
export function sanitizeHomeContent(html: string): string {
  if (!html) return ''
  return DOMPurify.sanitize(html, {
    FORCE_BODY: true,
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allowfullscreen', 'frameborder', 'target']
  })
}
