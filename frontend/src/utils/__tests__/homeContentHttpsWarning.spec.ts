import { describe, it, expect } from 'vitest'
import {
  looksLikeDangerousHomeScheme,
  looksLikeMalformedHomeUrlToken,
  looksLikeUnsupportedHomeSchemeToken,
  shouldWarnHomeContentHttp
} from '../homeContentHttpsWarning'

describe('shouldWarnHomeContentHttp (F-2)', () => {
  it('https URL 不提示', () => {
    expect(shouldWarnHomeContentHttp('https://example.com/home')).toBe(false)
    expect(shouldWarnHomeContentHttp('  HTTPS://example.com/home  ')).toBe(false)
  })

  it('http URL（含大小写）提示', () => {
    expect(shouldWarnHomeContentHttp('http://example.com/home')).toBe(true)
    expect(shouldWarnHomeContentHttp('HTTP://example.com/home')).toBe(true)
    expect(shouldWarnHomeContentHttp('  hTtP://example.com  ')).toBe(true)
  })

  it('无法解析为 https 绝对地址的 URL 模式内容提示', () => {
    expect(shouldWarnHomeContentHttp('https://[::1/x')).toBe(true)
    expect(shouldWarnHomeContentHttp('https:///')).toBe(true)
  })

  it('富文本含 http iframe 提示；仅 https iframe 不提示', () => {
    expect(shouldWarnHomeContentHttp('<p>hi</p><iframe src="http://a.example"></iframe>')).toBe(true)
    expect(shouldWarnHomeContentHttp('<iframe src="https://a.example"></iframe>')).toBe(false)
    expect(shouldWarnHomeContentHttp('<iframe src="HTTP://a.example"></iframe>')).toBe(true)
  })

  it('富文本含无 src / 空 src iframe 提示（会被清洗掉）', () => {
    expect(shouldWarnHomeContentHttp('<iframe></iframe>')).toBe(true)
    expect(shouldWarnHomeContentHttp('<iframe src=""></iframe>')).toBe(true)
  })

  it('空内容和不含 iframe 的 HTML 不提示', () => {
    expect(shouldWarnHomeContentHttp('')).toBe(false)
    expect(shouldWarnHomeContentHttp('   ')).toBe(false)
    expect(shouldWarnHomeContentHttp('<h1>hello</h1><p>world</p>')).toBe(false)
  })

  it('FD2-4：明显误填的 URL 形态提示（正例）', () => {
    expect(shouldWarnHomeContentHttp('https:a.com')).toBe(true)
    expect(shouldWarnHomeContentHttp('http:/a.com')).toBe(true)
    expect(shouldWarnHomeContentHttp('//a.com')).toBe(true)
    expect(shouldWarnHomeContentHttp('javascript:alert(1)')).toBe(true)
    expect(shouldWarnHomeContentHttp('data:text/html,hi')).toBe(true)
  })

  it('FD2-8：正文 / 非地址 token 不提示（反例）', () => {
    expect(shouldWarnHomeContentHttp('data: 今日数据更新')).toBe(false)
    expect(shouldWarnHomeContentHttp('http:说明文字')).toBe(false)
    expect(shouldWarnHomeContentHttp('just some text')).toBe(false)
    expect(shouldWarnHomeContentHttp('http: 说明')).toBe(false)
    expect(shouldWarnHomeContentHttp('see data:text/html,hi later')).toBe(false)
  })
})

describe('looksLikeDangerousHomeScheme (FD2-12)', () => {
  it('detects javascript / data / vbscript with mixed case', () => {
    expect(looksLikeDangerousHomeScheme('JavaScript:alert(1)')).toBe(true)
    expect(looksLikeDangerousHomeScheme('DATA:text/html,x')).toBe(true)
    expect(looksLikeDangerousHomeScheme('VbScript:msgbox(1)')).toBe(true)
  })

  it('detects leading whitespace / control characters', () => {
    expect(looksLikeDangerousHomeScheme('\tjavascript:alert(1)')).toBe(true)
    expect(looksLikeDangerousHomeScheme('\n\r  data:text/html,hi')).toBe(true)
    expect(looksLikeDangerousHomeScheme('\x00vbscript:x')).toBe(true)
  })

  it('detects whitespace / tab / newline inside the scheme name', () => {
    expect(looksLikeDangerousHomeScheme('java\tscript:alert(1)')).toBe(true)
    expect(looksLikeDangerousHomeScheme('java\nscript:alert(1)')).toBe(true)
    expect(looksLikeDangerousHomeScheme('d ata:text/html,x')).toBe(true)
  })

  it('warns when payload after colon contains spaces (not bound by single-token)', () => {
    expect(shouldWarnHomeContentHttp('javascript:alert("中")')).toBe(true)
    expect(shouldWarnHomeContentHttp('javascript:alert("hello world")')).toBe(true)
    expect(
      shouldWarnHomeContentHttp('data:text/html,<script>alert(1)</script>')
    ).toBe(true)
  })

  it('data: with whitespace immediately after colon is NOT dangerous (prose conflict)', () => {
    // Positive: dangerous only when first char after ':' is non-whitespace
    expect(looksLikeDangerousHomeScheme('data:text/html,hi')).toBe(true)
    expect(looksLikeDangerousHomeScheme('data:')).toBe(true)
    // Negative: 「data: 今日数据更新」— space after colon → not dangerous;
    // FD2-8 single-token also rejects → overall no tip.
    expect(looksLikeDangerousHomeScheme('data: 今日数据更新')).toBe(false)
    expect(shouldWarnHomeContentHttp('data: 今日数据更新')).toBe(false)
    expect(looksLikeDangerousHomeScheme('javascript: alert(1)')).toBe(false)
  })
})

describe('looksLikeUnsupportedHomeSchemeToken (FD2-12)', () => {
  it('tips file / ftp / mailto as unsupported on a single token', () => {
    expect(looksLikeUnsupportedHomeSchemeToken('file:///etc/passwd')).toBe(true)
    expect(looksLikeUnsupportedHomeSchemeToken('ftp://host/a')).toBe(true)
    expect(looksLikeUnsupportedHomeSchemeToken('ftp:/a')).toBe(true)
    expect(looksLikeUnsupportedHomeSchemeToken('mailto:a@b.com')).toBe(true)
    expect(shouldWarnHomeContentHttp('ftp:/a')).toBe(true)
    expect(shouldWarnHomeContentHttp('mailto:a@b.com')).toBe(true)
  })

  it('keeps single-token rule so spaced prose does not tip', () => {
    expect(looksLikeUnsupportedHomeSchemeToken('ftp: 说明')).toBe(false)
    expect(shouldWarnHomeContentHttp('ftp: 说明')).toBe(false)
    expect(shouldWarnHomeContentHttp('mailto: hello')).toBe(false)
  })
})

describe('looksLikeMalformedHomeUrlToken (FD2-8)', () => {
  it('requires a single whitespace-free token', () => {
    expect(looksLikeMalformedHomeUrlToken('data: 今日数据更新')).toBe(false)
    expect(looksLikeMalformedHomeUrlToken('http: 说明')).toBe(false)
  })

  it('rejects non-ASCII rest after scheme (prose)', () => {
    expect(looksLikeMalformedHomeUrlToken('http:说明文字')).toBe(false)
  })

  it('accepts malformed http(s) and protocol-relative', () => {
    expect(looksLikeMalformedHomeUrlToken('https:a.com')).toBe(true)
    expect(looksLikeMalformedHomeUrlToken('http:/a.com')).toBe(true)
    expect(looksLikeMalformedHomeUrlToken('//a.com')).toBe(true)
  })
})
