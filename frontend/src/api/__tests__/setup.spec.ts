import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  __setupClientTestOnly,
  getSetupStatus,
  testDatabase,
  setSetupToken,
  getSetupToken,
  normalizeSetupError,
  setupTokenUserMessage,
  SETUP_TOKEN_INVALID,
  SETUP_TOKEN_REQUIRED,
  SETUP_TOKEN_RATE_LIMITED
} from '../setup'
import enLanding from '@/i18n/locales/en/landing'
import zhLanding from '@/i18n/locales/zh/landing'

function okAdapter(data: unknown) {
  return vi.fn().mockResolvedValue({
    status: 200,
    data,
    headers: {},
    config: {},
    statusText: 'OK'
  })
}

describe('setup API (F-5)', () => {
  beforeEach(() => {
    setSetupToken('')
    // Clear any leftover adapter between tests
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(__setupClientTestOnly.defaults as any).adapter = undefined
  })

  it('exposes setup_token_required from status', async () => {
    const adapter = okAdapter({
      data: { needs_setup: true, step: 'database', setup_token_required: true }
    })
    __setupClientTestOnly.defaults.adapter = adapter
    const status = await getSetupStatus()
    expect(status.setup_token_required).toBe(true)
    expect(adapter).toHaveBeenCalled()
  })

  it('attaches X-Setup-Token to test-db when set', async () => {
    setSetupToken('  aabbccddeeff00112233445566778899  ')
    expect(getSetupToken()).toBe('aabbccddeeff00112233445566778899')
    const adapter = okAdapter({ data: { ok: true } })
    __setupClientTestOnly.defaults.adapter = adapter
    await testDatabase({
      host: 'localhost',
      port: 5432,
      user: 'u',
      password: 'p',
      dbname: 'db',
      sslmode: 'disable'
    })
    const config = adapter.mock.calls[0][0]
    const header =
      typeof config.headers?.get === 'function'
        ? config.headers.get('X-Setup-Token')
        : config.headers?.['X-Setup-Token']
    expect(header).toBe('aabbccddeeff00112233445566778899')
  })

  it('omits X-Setup-Token when empty', async () => {
    const adapter = okAdapter({ data: { ok: true } })
    __setupClientTestOnly.defaults.adapter = adapter
    await testDatabase({
      host: 'localhost',
      port: 5432,
      user: 'u',
      password: 'p',
      dbname: 'db',
      sslmode: 'disable'
    })
    const config = adapter.mock.calls[0][0]
    const header =
      typeof config.headers?.get === 'function'
        ? config.headers.get('X-Setup-Token')
        : config.headers?.['X-Setup-Token']
    expect(header).toBeFalsy()
  })

  it('normalizeSetupError reads reason message and Retry-After', () => {
    const err = {
      message: 'Request failed',
      response: {
        status: 429,
        headers: { 'retry-after': '30' },
        data: {
          code: 429,
          reason: SETUP_TOKEN_RATE_LIMITED,
          message: '尝试过多，请稍后再试'
        }
      }
    }
    const n = normalizeSetupError(err)
    expect(n.reason).toBe(SETUP_TOKEN_RATE_LIMITED)
    expect(n.message).toBe('尝试过多，请稍后再试')
    expect(n.retryAfter).toBe(30)
    expect(n.status).toBe(429)
  })

  it('normalizeSetupError parses Retry-After HTTP-date into remaining seconds', () => {
    const future = new Date(Date.now() + 45_000).toUTCString()
    const n = normalizeSetupError({
      response: {
        status: 429,
        headers: { 'retry-after': future },
        data: { code: 429, reason: SETUP_TOKEN_RATE_LIMITED, message: 'slow down' }
      }
    })
    expect(n.retryAfter).toBeGreaterThanOrEqual(40)
    expect(n.retryAfter).toBeLessThanOrEqual(45)
  })

  it('normalizeSetupError maps invalid / required reasons', () => {
    expect(
      normalizeSetupError({
        response: {
          status: 403,
          headers: {},
          data: { code: 403, reason: SETUP_TOKEN_INVALID, message: 'bad token' }
        }
      }).reason
    ).toBe(SETUP_TOKEN_INVALID)
    expect(
      normalizeSetupError({
        response: {
          status: 401,
          headers: {},
          data: { code: 401, reason: SETUP_TOKEN_REQUIRED, message: 'need token' }
        }
      }).reason
    ).toBe(SETUP_TOKEN_REQUIRED)
  })
})

describe('setupTokenUserMessage (FD2-14 / FD2-17)', () => {
  function tFor(locale: 'en' | 'zh') {
    const root = locale === 'en' ? enLanding : zhLanding
    return (key: string, params?: Record<string, unknown>) => {
      let cur: unknown = root
      for (const part of key.split('.')) {
        cur = (cur as Record<string, unknown>)?.[part]
      }
      if (typeof cur !== 'string') return key
      if (!params) return cur
      return cur.replace(/\{(\w+)\}/g, (_: string, name: string) =>
        String(params[name] ?? '')
      )
    }
  }

  it('uses zh frontend copy for REQUIRED / INVALID / RATE_LIMITED (ignores backend message)', () => {
    const t = tFor('zh')
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_REQUIRED, message: 'need token' } as never, t)
    ).toBe(zhLanding.setup.setupToken.required)
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_INVALID, message: 'bad token from BE' } as never, t)
    ).toBe(zhLanding.setup.setupToken.invalid)
    expect(
      setupTokenUserMessage(
        { reason: SETUP_TOKEN_RATE_LIMITED, retryAfter: 30, message: '后端中文消息' } as never,
        t
      )
    ).toBe('尝试过多，请 30 秒后再试')
  })

  it('uses en frontend copy for REQUIRED / INVALID / RATE_LIMITED', () => {
    const t = tFor('en')
    expect(setupTokenUserMessage({ reason: SETUP_TOKEN_REQUIRED }, t)).toBe(
      enLanding.setup.setupToken.required
    )
    expect(setupTokenUserMessage({ reason: SETUP_TOKEN_INVALID }, t)).toBe(
      enLanding.setup.setupToken.invalid
    )
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED, retryAfter: 45 }, t)
    ).toBe('Too many attempts. Try again in 45s')
  })

  it('FD2-17: RATE_LIMITED without Retry-After uses no-wait copy (zh + en)', () => {
    expect(setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED }, tFor('en'))).toBe(
      enLanding.setup.setupToken.rateLimitedNoWait
    )
    expect(setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED }, tFor('zh'))).toBe(
      zhLanding.setup.setupToken.rateLimitedNoWait
    )
  })

  it('FD2-17: RATE_LIMITED with retryAfter 0 or invalid uses no-wait copy', () => {
    const t = tFor('en')
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED, retryAfter: 0 }, t)
    ).toBe(enLanding.setup.setupToken.rateLimitedNoWait)
    // normalizeSetupError leaves retryAfter undefined when header unparseable
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED, retryAfter: undefined }, t)
    ).toBe(enLanding.setup.setupToken.rateLimitedNoWait)
  })

  it('FD2-17: seconds template only when retryAfter > 0', () => {
    const t = tFor('zh')
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED, retryAfter: 1 }, t)
    ).toBe('尝试过多，请 1 秒后再试')
    expect(
      setupTokenUserMessage({ reason: SETUP_TOKEN_RATE_LIMITED, retryAfter: 0 }, t)
    ).toBe(zhLanding.setup.setupToken.rateLimitedNoWait)
  })

  it('FD2-17: HTTP 429 without reason uses FE rate-limit copy (not backend message)', () => {
    const tEn = tFor('en')
    const tZh = tFor('zh')
    expect(
      setupTokenUserMessage(
        { status: 429, message: 'slow down from backend' } as never,
        tEn
      )
    ).toBe(enLanding.setup.setupToken.rateLimitedNoWait)
    expect(
      setupTokenUserMessage(
        { status: 429, retryAfter: 12, message: '后端随便写的' } as never,
        tZh
      )
    ).toBe('尝试过多，请 12 秒后再试')
  })

  it('returns null for non-token non-429 errors', () => {
    const t = tFor('en')
    expect(setupTokenUserMessage({ reason: 'OTHER' }, t)).toBeNull()
    expect(setupTokenUserMessage({ status: 500 }, t)).toBeNull()
    expect(setupTokenUserMessage({}, t)).toBeNull()
  })

  it('FD2-18: non-setup reason on HTTP 429 returns null (not wizard rate-limit copy)', () => {
    const t = tFor('en')
    expect(
      setupTokenUserMessage(
        { reason: 'TOTP_TOO_MANY_ATTEMPTS', status: 429, retryAfter: 30, message: 'too many' } as never,
        t
      )
    ).toBeNull()
    expect(
      setupTokenUserMessage(
        { reason: 'OTHER', status: 429, retryAfter: 12 } as never,
        t
      )
    ).toBeNull()
    expect(
      setupTokenUserMessage({ reason: 'STEP_UP_REQUIRED', status: 429 } as never, t)
    ).toBeNull()
  })

  it('FD2-18: known SETUP_TOKEN_* reasons still map when status is also 429', () => {
    const t = tFor('zh')
    expect(
      setupTokenUserMessage(
        { reason: SETUP_TOKEN_REQUIRED, status: 429, message: 'be' } as never,
        t
      )
    ).toBe(zhLanding.setup.setupToken.required)
    expect(
      setupTokenUserMessage(
        { reason: SETUP_TOKEN_INVALID, status: 429, message: 'be' } as never,
        t
      )
    ).toBe(zhLanding.setup.setupToken.invalid)
    expect(
      setupTokenUserMessage(
        { reason: SETUP_TOKEN_RATE_LIMITED, status: 429, retryAfter: 8, message: 'be' } as never,
        t
      )
    ).toBe('尝试过多，请 8 秒后再试')
  })
})
