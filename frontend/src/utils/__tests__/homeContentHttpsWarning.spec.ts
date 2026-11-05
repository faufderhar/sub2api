import { describe, it, expect } from 'vitest'
import {
  looksLikeMalformedHomeUrlToken,
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
    expect(shouldWarnHomeContentHttp('ftp:/a')).toBe(false)
    expect(shouldWarnHomeContentHttp('just some text')).toBe(false)
    expect(shouldWarnHomeContentHttp('http: 说明')).toBe(false)
    expect(shouldWarnHomeContentHttp('see data:text/html,hi later')).toBe(false)
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

  it('rejects unrelated schemes like ftp', () => {
    expect(looksLikeMalformedHomeUrlToken('ftp:/a')).toBe(false)
  })

  it('accepts malformed http(s)/javascript/data and protocol-relative', () => {
    expect(looksLikeMalformedHomeUrlToken('https:a.com')).toBe(true)
    expect(looksLikeMalformedHomeUrlToken('http:/a.com')).toBe(true)
    expect(looksLikeMalformedHomeUrlToken('//a.com')).toBe(true)
    expect(looksLikeMalformedHomeUrlToken('javascript:alert(1)')).toBe(true)
    expect(looksLikeMalformedHomeUrlToken('data:text/html,hi')).toBe(true)
  })
})
