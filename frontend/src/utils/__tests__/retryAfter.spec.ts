import { describe, expect, it } from 'vitest'
import { parseRetryAfter } from '../retryAfter'

describe('parseRetryAfter (FD2-3)', () => {
  it('parses delay-seconds', () => {
    expect(parseRetryAfter('30')).toBe(30)
    expect(parseRetryAfter('0')).toBe(0)
    expect(parseRetryAfter(' 120 ')).toBe(120)
    expect(parseRetryAfter('+5')).toBe(5)
  })

  it('parses HTTP-date into remaining seconds', () => {
    const now = Date.parse('Thu, 05 Nov 2026 05:45:00 GMT')
    expect(parseRetryAfter('Thu, 05 Nov 2026 05:45:58 GMT', now)).toBe(58)
  })

  it('clamps past HTTP-date to 0', () => {
    const now = Date.parse('Thu, 05 Nov 2026 05:46:00 GMT')
    expect(parseRetryAfter('Thu, 05 Nov 2026 05:45:58 GMT', now)).toBe(0)
  })

  it('returns undefined for unparseable values', () => {
    expect(parseRetryAfter(undefined)).toBeUndefined()
    expect(parseRetryAfter('')).toBeUndefined()
    expect(parseRetryAfter('soon')).toBeUndefined()
    expect(parseRetryAfter('12.5')).toBeUndefined()
    expect(parseRetryAfter('30s')).toBeUndefined()
  })
})
