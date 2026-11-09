import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import DOMPurify from 'dompurify'
import { sanitizeHomeContent, sanitizeSvg, isHttpsAbsoluteUrl, resolveHomeIframeSandbox, HOME_IFRAME_SANDBOX_DEFAULT } from '../sanitize'

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
    expect(iframe.getAttribute('sandbox')).toBe('allow-scripts')
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

  describe('iframe 只允许 https 绝对地址', () => {
    const iframes = (html: string) =>
      new DOMParser().parseFromString(sanitizeHomeContent(html), 'text/html').querySelectorAll('iframe')

    const rejected: Array<[string, string]> = [
      ['http:', '<iframe src="http://example.com/embed"></iframe>'],
      ['HTTP 大写', '<iframe src="HTTP://example.com/embed"></iframe>'],
      ['相对路径', '<iframe src="/home"></iframe>'],
      ['相对路径（无斜杠）', '<iframe src="embed.html"></iframe>'],
      ['协议相对 //host', '<iframe src="//example.com/embed"></iframe>'],
      ['反斜杠协议相对', '<iframe src="\\\\example.com/embed"></iframe>'],
      ['javascript:', '<iframe src="javascript:alert(1)"></iframe>'],
      ['JavaScript 大小写', '<iframe src="JaVaScRiPt:alert(1)"></iframe>'],
      ['javascript 前导空白', '<iframe src="  javascript:alert(1)"></iframe>'],
      ['javascript 中间制表符（实体编码）', '<iframe src="java&#x09;script:alert(1)"></iframe>'],
      ['javascript 冒号实体编码', '<iframe src="javascript&colon;alert(1)"></iframe>'],
      ['data:', '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>'],
      ['DATA 大写', '<iframe src="DATA:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>'],
      ['blob:', '<iframe src="blob:https://example.com/uuid"></iframe>'],
      ['vbscript:', '<iframe src="vbscript:msgbox(1)"></iframe>'],
      ['file:', '<iframe src="file:///etc/passwd"></iframe>'],
      ['ftp:', '<iframe src="ftp://example.com/x"></iframe>'],
      ['没有 src', '<iframe></iframe>'],
      ['空 src', '<iframe src=""></iframe>'],
      ['空白 src', '<iframe src="   "></iframe>'],
      ['百分号编码协议', '<iframe src="%68ttps://example.com"></iframe>'],
      ['仅 https: 无主机', '<iframe src="https:"></iframe>'],
      ['srcdoc 无 src', '<iframe srcdoc="<script>alert(1)</script>"></iframe>'],
      ['srcdoc + http', '<iframe src="http://example.com" srcdoc="x"></iframe>']
    ]
    it.each(rejected)('移除：%s', (_name, html) => {
      const out = sanitizeHomeContent('<p>before</p>' + html + '<p>after</p>')
      expect(out).not.toMatch(/<iframe/i)
      expect(out).toContain('<p>before</p>')
      expect(out).toContain('<p>after</p>')
    })

    it('嵌套和混排：只移除不合法的那一个', () => {
      const list = iframes(
        '<div><iframe src="http://a.example"></iframe><iframe src="https://b.example/embed"></iframe></div>' +
        '<section><iframe src="//c.example"></iframe></section>'
      )
      expect(list).toHaveLength(1)
      expect(list[0].getAttribute('src')).toBe('https://b.example/embed')
    })

    it('保留合法的 https iframe 及其属性（含大写 HTTPS、首尾空白）', () => {
      const list = iframes(
        '<iframe src="https://www.youtube.com/embed/x" width="560" height="315" frameborder="0" allowfullscreen="" ' +
        'sandbox="allow-scripts allow-same-origin" allow="autoplay; fullscreen; picture-in-picture" ' +
        'referrerpolicy="strict-origin-when-cross-origin" loading="lazy" title="v" class="c" style="border:0"></iframe>' +
        '<iframe src="HTTPS://player.bilibili.com/player.html?bvid=1"></iframe>' +
        '<iframe src=" https://example.com/padded "></iframe>'
      )
      expect(list).toHaveLength(3)
      const f = list[0]
      expect(f.getAttribute('src')).toBe('https://www.youtube.com/embed/x')
      expect(f.getAttribute('width')).toBe('560')
      expect(f.getAttribute('height')).toBe('315')
      expect(f.getAttribute('frameborder')).toBe('0')
      expect(f.hasAttribute('allowfullscreen')).toBe(true)
      expect(f.getAttribute('sandbox')).toBe('allow-scripts')
      expect(f.getAttribute('allow')).toBe('autoplay; fullscreen; picture-in-picture')
      expect(f.getAttribute('referrerpolicy')).toBe('strict-origin-when-cross-origin')
      expect(f.getAttribute('loading')).toBe('lazy')
      expect(f.getAttribute('title')).toBe('v')
      expect(f.getAttribute('class')).toBe('c')
      expect(f.getAttribute('style')).toBe('border:0')
    })

    it('isHttpsAbsoluteUrl 基于 URL 解析', () => {
      expect(isHttpsAbsoluteUrl('https://example.com')).toBe(true)
      expect(isHttpsAbsoluteUrl('HTTPS://EXAMPLE.com/x')).toBe(true)
      expect(isHttpsAbsoluteUrl('https://example.com.evil.test')).toBe(true)
      expect(isHttpsAbsoluteUrl('http://example.com')).toBe(false)
      expect(isHttpsAbsoluteUrl('//example.com')).toBe(false)
      expect(isHttpsAbsoluteUrl('/x')).toBe(false)
      expect(isHttpsAbsoluteUrl('java\tscript:alert(1)')).toBe(false)
      expect(isHttpsAbsoluteUrl('https:')).toBe(false)
      expect(isHttpsAbsoluteUrl('')).toBe(false)
      expect(isHttpsAbsoluteUrl(null)).toBe(false)
    })

    it('只作用于首页实例：全局 DOMPurify 仍保留 http iframe', () => {
      sanitizeHomeContent('<iframe src="http://example.com"></iframe>')
      expect(DOMPurify.sanitize('<iframe src="http://example.com"></iframe>', { ADD_TAGS: ['iframe'] }))
        .toContain('<iframe src="http://example.com">')
    })
  })


  describe('F-1：首页 iframe 统一 sandbox（默认 + 交集不放宽）', () => {
    const DEFAULT = HOME_IFRAME_SANDBOX_DEFAULT.join(' ')

    it('未写 sandbox 时写入默认全集', () => {
      const out = sanitizeHomeContent('<iframe src="https://example.com/embed"></iframe>')
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe(DEFAULT)
    })

    it('管理员写更严的 sandbox 被保留（取交集）', () => {
      const out = sanitizeHomeContent(
        '<iframe src="https://example.com/embed" sandbox="allow-scripts allow-popups"></iframe>'
      )
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-popups')
    })

    it('管理员写空 sandbox（最严）仍为空，不放宽成默认', () => {
      const out = sanitizeHomeContent('<iframe src="https://example.com/embed" sandbox=""></iframe>')
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe('')
    })

    it('管理员写超出默认集合的 token（如 allow-top-navigation）被去掉', () => {
      const out = sanitizeHomeContent(
        '<iframe src="https://example.com/embed" sandbox="allow-scripts allow-top-navigation allow-popups allow-modals"></iframe>'
      )
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-popups')
      expect(iframe.getAttribute('sandbox')).not.toContain('allow-top-navigation')
      expect(iframe.getAttribute('sandbox')).not.toContain('allow-modals')
    })

    it('resolveHomeIframeSandbox 单元行为', () => {
      expect(resolveHomeIframeSandbox(null)).toBe(DEFAULT)
      expect(resolveHomeIframeSandbox(undefined)).toBe(DEFAULT)
      expect(resolveHomeIframeSandbox('')).toBe('')
      expect(resolveHomeIframeSandbox('allow-scripts allow-forms')).toBe('allow-scripts allow-forms')
      expect(resolveHomeIframeSandbox('ALLOW-SCRIPTS allow-modals')).toBe('allow-scripts')
    })
  })


  describe('A-1 / R3-IFRAME：所有不可信 iframe 都不含 allow-same-origin', () => {
    const NO_SAME = HOME_IFRAME_SANDBOX_DEFAULT.filter((t) => t !== 'allow-same-origin').join(' ')
    const pageOrigin = 'https://app.test'
    const pageHref = 'https://app.test/admin/settings'

    beforeEach(() => {
      vi.stubGlobal('location', {
        href: pageHref,
        origin: pageOrigin,
        protocol: 'https:',
        host: 'app.test',
        hostname: 'app.test',
        port: '',
        pathname: '/admin/settings',
        search: '',
        hash: ''
      })
    })

    afterEach(() => {
      vi.unstubAllGlobals()
    })

    it('相对路径在 resolve 层视为同源（富文本仍只保留 https，相对 iframe 会被清洗掉）', () => {
      expect(resolveHomeIframeSandbox(null, '/home-embed')).toBe(NO_SAME)
      // 富文本 L-1：非 https 绝对地址的 iframe 整段移除
      expect(sanitizeHomeContent('<iframe src="/home-embed"></iframe>')).not.toContain('<iframe')
    })

    it('与页面同源的 https iframe 去掉 allow-same-origin', () => {
      const same = `${pageOrigin}/embed`
      const out = sanitizeHomeContent(`<iframe src="${same}"></iframe>`)
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe(NO_SAME)
      expect(iframe.getAttribute('sandbox')).not.toContain('allow-same-origin')
    })

    it('跨域 https 也不带 allow-same-origin（不依赖初始 src）', () => {
      const out = sanitizeHomeContent('<iframe src="https://example.com/embed"></iframe>')
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe(NO_SAME)
      expect(iframe.getAttribute('sandbox')).not.toContain('allow-same-origin')
    })

    it('管理员自写 sandbox 含 allow-same-origin 时跨域也被去掉', () => {
      const out = sanitizeHomeContent(
        '<iframe src="https://example.com/embed" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>'
      )
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-forms')
      expect(iframe.getAttribute('sandbox')).not.toContain('allow-same-origin')
    })

    it('管理员自写 sandbox 含 allow-same-origin 时同源仍被去掉', () => {
      const same = `${pageOrigin}/local`
      const out = sanitizeHomeContent(
        `<iframe src="${same}" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>`
      )
      const iframe = new DOMParser().parseFromString(out, 'text/html').querySelector('iframe')!
      expect(iframe.getAttribute('sandbox')).toBe('allow-scripts allow-forms')
      expect(iframe.getAttribute('sandbox')).not.toContain('allow-same-origin')
    })

    it('resolveHomeIframeSandbox 对任意 src 都去掉 allow-same-origin', () => {
      expect(resolveHomeIframeSandbox(null, '/x')).toBe(NO_SAME)
      expect(resolveHomeIframeSandbox(null, `${pageOrigin}/x`)).toBe(NO_SAME)
      expect(resolveHomeIframeSandbox(null, 'https://example.com/x')).toBe(NO_SAME)
      expect(
        resolveHomeIframeSandbox('allow-scripts allow-same-origin', '/x')
      ).toBe('allow-scripts')
      expect(
        resolveHomeIframeSandbox('allow-scripts allow-same-origin', 'https://example.com/x')
      ).toBe('allow-scripts')
    })
  })

  it('空内容返回空字符串', () => {
    expect(sanitizeHomeContent('')).toBe('')
  })
})
