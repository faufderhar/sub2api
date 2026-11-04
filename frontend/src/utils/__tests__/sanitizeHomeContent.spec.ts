import { describe, it, expect } from 'vitest'
import { sanitizeHomeContent } from '../sanitize'

describe('sanitizeHomeContent (L-1)', () => {
  it('去掉 <script>、on* 事件属性和 javascript: 链接', () => {
    const out = sanitizeHomeContent(
      '<img src=x onerror=alert(1)><script>alert(2)</script>' +
      '<a href="javascript:alert(3)">a</a><div onclick="alert(4)">d</div>' +
      '<svg><animate onbegin=alert(5) attributeName=x dur=1s></svg>' +
      '<iframe srcdoc="<script>alert(6)</script>"></iframe><iframe src="javascript:alert(7)"></iframe>'
    )
    expect(out).not.toMatch(/<script/i)
    expect(out).not.toMatch(/onerror|onclick|onbegin/i)
    expect(out).not.toMatch(/javascript:/i)
    expect(out).not.toMatch(/srcdoc/i)
    expect(out).toContain('<img src="x">')
  })

  it('保留正常格式：开头的 <style>、class、内联 style、标题/列表/表格、图片、链接 target、iframe 嵌入', () => {
    const html =
      '<style>.hero{color:red}</style>' +
      '<div class="hero" style="padding: 8px"><h1>Title</h1><p><strong>b</strong> <em>i</em></p>' +
      '<ul><li>x</li></ul><table><tbody><tr><td>c</td></tr></tbody></table>' +
      '<img src="https://example.com/a.png" alt="a">' +
      '<a href="https://example.com" target="_blank" rel="noopener">link</a>' +
      '<iframe src="https://www.youtube.com/embed/x" frameborder="0" allowfullscreen=""></iframe></div>'
    const out = sanitizeHomeContent(html)
    expect(out).toContain('<style>.hero{color:red}</style>')
    expect(out).toContain('class="hero"')
    expect(out).toContain('style="padding: 8px"')
    expect(out).toContain('<h1>Title</h1>')
    expect(out).toContain('<table>')
    expect(out).toContain('src="https://example.com/a.png"')
    expect(out).toContain('target="_blank"')
    expect(out).toContain('<iframe src="https://www.youtube.com/embed/x"')
  })

  it('空内容返回空字符串', () => {
    expect(sanitizeHomeContent('')).toBe('')
  })
})
