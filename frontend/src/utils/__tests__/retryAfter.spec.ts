import { describe, expect, it } from 'vitest'
import {
  RETRY_AFTER_MAX_SECONDS,
  clampRetryAfterSeconds,
  parseHttpDateUtc,
  parseRetryAfter
} from '../retryAfter'

describe('parseHttpDateUtc (FD2-6)', () => {
  it('parses IMF-fixdate as UTC', () => {
    expect(parseHttpDateUtc('Sun, 06 Nov 1994 08:49:37 GMT')).toBe(
      Date.UTC(1994, 10, 6, 8, 49, 37)
    )
    expect(parseHttpDateUtc('Thu, 05 Nov 2026 05:45:58 GMT')).toBe(
      Date.UTC(2026, 10, 5, 5, 45, 58)
    )
  })

  it('parses RFC 850 as UTC', () => {
    expect(parseHttpDateUtc('Sunday, 06-Nov-94 08:49:37 GMT')).toBe(
      Date.UTC(1994, 10, 6, 8, 49, 37)
    )
  })

  it('parses asctime as UTC (not local time)', () => {
    // Space-padded day — classic asctime form from RFC 9110 examples.
    expect(parseHttpDateUtc('Sun Nov  6 08:49:37 1994')).toBe(
      Date.UTC(1994, 10, 6, 8, 49, 37)
    )
    expect(parseHttpDateUtc('Thu Nov  5 06:00:10 2026')).toBe(
      Date.UTC(2026, 10, 5, 6, 0, 10)
    )
  })

  it('asctime remaining seconds are timezone-independent', () => {
    // Fixed "now" = Thu Nov 5 06:00:00 2026 UTC.
    // If asctime were parsed as America/Los_Angeles (UTC-8), remaining would be ~28810.
    const now = Date.UTC(2026, 10, 5, 6, 0, 0)
    expect(parseRetryAfter('Thu Nov  5 06:00:10 2026', now)).toBe(10)
  })

  it('rejects non-HTTP-date text', () => {
    expect(parseHttpDateUtc('soon')).toBeUndefined()
    expect(parseHttpDateUtc('12.5')).toBeUndefined()
    expect(parseHttpDateUtc('')).toBeUndefined()
  })
})

describe('clampRetryAfterSeconds (FD2-7)', () => {
  it('clamps NaN and negatives to 0', () => {
    expect(clampRetryAfterSeconds(Number.NaN)).toBe(0)
    expect(clampRetryAfterSeconds(-1)).toBe(0)
    expect(clampRetryAfterSeconds(-1e9)).toBe(0)
    expect(clampRetryAfterSeconds(Number.NEGATIVE_INFINITY)).toBe(0)
  })

  it('caps at 86400', () => {
    expect(clampRetryAfterSeconds(86400)).toBe(86400)
    expect(clampRetryAfterSeconds(86401)).toBe(RETRY_AFTER_MAX_SECONDS)
    expect(clampRetryAfterSeconds(1e20)).toBe(RETRY_AFTER_MAX_SECONDS)
    expect(clampRetryAfterSeconds(Number.POSITIVE_INFINITY)).toBe(0)
  })
})

describe('parseRetryAfter (FD2-3 / FD2-6 / FD2-7)', () => {
  it('parses delay-seconds', () => {
    expect(parseRetryAfter('30')).toBe(30)
    expect(parseRetryAfter('0')).toBe(0)
    expect(parseRetryAfter(' 120 ')).toBe(120)
    expect(parseRetryAfter('+5')).toBe(5)
  })

  it('treats negative delay-seconds as 0', () => {
    expect(parseRetryAfter('-5')).toBe(0)
  })

  it('caps huge delay-seconds at 86400', () => {
    expect(parseRetryAfter('999999')).toBe(RETRY_AFTER_MAX_SECONDS)
    expect(parseRetryAfter(String(RETRY_AFTER_MAX_SECONDS))).toBe(86400)
  })

  it('parses IMF-fixdate into remaining seconds', () => {
    const now = Date.UTC(2026, 10, 5, 5, 45, 0)
    expect(parseRetryAfter('Thu, 05 Nov 2026 05:45:58 GMT', now)).toBe(58)
  })

  it('parses RFC 850 into remaining seconds as UTC', () => {
    const now = Date.UTC(1994, 10, 6, 8, 49, 0)
    expect(parseRetryAfter('Sunday, 06-Nov-94 08:49:37 GMT', now)).toBe(37)
  })

  it('clamps past HTTP-date to 0', () => {
    const now = Date.UTC(2026, 10, 5, 5, 46, 0)
    expect(parseRetryAfter('Thu, 05 Nov 2026 05:45:58 GMT', now)).toBe(0)
  })

  it('caps far-future HTTP-date remaining seconds at 86400', () => {
    const now = Date.UTC(2026, 10, 5, 0, 0, 0)
    expect(parseRetryAfter('Fri, 06 Nov 2026 12:00:00 GMT', now)).toBe(
      RETRY_AFTER_MAX_SECONDS
    )
  })

  it('returns undefined for unparseable values', () => {
    expect(parseRetryAfter(undefined)).toBeUndefined()
    expect(parseRetryAfter('')).toBeUndefined()
    expect(parseRetryAfter('soon')).toBeUndefined()
    expect(parseRetryAfter('12.5')).toBeUndefined()
    expect(parseRetryAfter('30s')).toBeUndefined()
  })
})
