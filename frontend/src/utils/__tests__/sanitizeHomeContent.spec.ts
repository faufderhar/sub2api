import { describe, it, expect } from 'vitest'
import DOMPurify from 'dompurify'
import { sanitizeHomeContent, sanitizeSvg } from '../sanitize'

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

  it('D-2：保留 iframe 的 sandbox、allow、referrerpolicy、loading', () => {
    const out = sanitizeHomeContent(
      '<iframe src="https://example.com/embed" sandbox="allow-scripts allow-same-origin" ' +
      'allow="autoplay; fullscreen; picture-in-picture" referrerpolicy="strict-origin-when-cross-origin" loading="lazy"></iframe>'
    )
    const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
    expect(iframe.getAttribute('src')).toBe('https://example.com/embed')
    expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-same-origin')
    expect(iframe.getAttribute('allow')).toBe('autoplay; fullscreen; picture-in-picture')
    expect(iframe.getAttribute('referrerpolicy')).toBe('strict-origin-when-cross-origin')
    expect(iframe.getAttribute('loading')).toBe('lazy')
  })

  it('D-2：放开属性后危险协议和 srcdoc 仍被拦截', () => {
    const out = sanitizeHomeContent(
      '<iframe src="javascript:alert(1)" sandbox="allow-scripts"></iframe>' +
      '<iframe srcdoc="<script>alert(2)</script>" allow="autoplay"></iframe>'
    )
    expect(out).not.toMatch(/javascript:/i)
    expect(out).not.toMatch(/srcdoc/i)
  })

  it('D-3：target=_blank 的链接补上 rel="noopener noreferrer"，保留已有 rel 值', () => {
    const doc = (html: string) => new DOMParser().parseFromString(sanitizeHomeContent(html), 'text/html')
    const a1 = doc('<a href="https://example.com" target="_blank">ext</a>').querySelector('a')!
    expect(a1.getAttribute('rel')).toBe('noopener noreferrer')
    const a2 = doc('<a href="https://example.com" target="_BLANK" rel="nofollow noopener">ext</a>').querySelector('a')!
    expect(a2.getAttribute('rel')!.split(' ').sort()).toEqual(['nofollow', 'noopener', 'noreferrer'])
    const a3 = doc('<a href="https://example.com" target="_self">same</a><a href="/x">plain</a>').querySelectorAll('a')
    expect(a3[0].hasAttribute('rel')).toBe(false)
    expect(a3[1].hasAttribute('rel')).toBe(false)
  })

  it('D-3：hook 不污染全局 DOMPurify 及其他清洗函数', () => {
    sanitizeHomeContent('<a href="https://example.com" target="_blank">warm up</a>')
    const html = '<a href="https://example.com" target="_blank">ext</a>'
    expect(DOMPurify.sanitize(html, { ADD_ATTR: ['target'] })).toBe(html)
    expect(DOMPurify.sanitize(html, { ADD_ATTR: ['target'] })).not.toContain('rel=')
    expect(sanitizeSvg('<svg><a href="https://example.com" target="_blank"></a></svg>')).not.toContain('noreferrer')
  })

  it('空内容返回空字符串', () => {
    expect(sanitizeHomeContent('')).toBe('')
  })
})
