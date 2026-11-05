import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  __setupClientTestOnly,
  getSetupStatus,
  testDatabase,
  setSetupToken,
  getSetupToken,
  normalizeSetupError,
  SETUP_TOKEN_INVALID,
  SETUP_TOKEN_REQUIRED,
  SETUP_TOKEN_RATE_LIMITED
} from '../setup'

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
