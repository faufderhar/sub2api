import { describe, it, expect, vi } from 'vitest'
import {
  useStepUp,
  isStepUpRequired,
  isStepUpBlocked,
  isStepUpCancelled,
  stepUpBlockReason,
  stepUpBlockedMessage,
  StepUpCancelledError
} from '../useStepUp'

describe('useStepUp error classification', () => {
  it('detects STEP_UP_REQUIRED from code field', () => {
    expect(isStepUpRequired({ status: 403, code: 'STEP_UP_REQUIRED' })).toBe(true)
    expect(isStepUpRequired({ status: 403, reason: 'STEP_UP_REQUIRED' })).toBe(true)
    expect(isStepUpRequired({ status: 500, code: 'INTERNAL' })).toBe(false)
    expect(isStepUpRequired(null)).toBe(false)
  })

  it('detects blocked (non-retryable) step-up errors', () => {
    expect(isStepUpBlocked({ code: 'STEP_UP_TOTP_NOT_ENABLED' })).toBe(true)
    expect(isStepUpBlocked({ reason: 'STEP_UP_ADMIN_API_KEY_FORBIDDEN' })).toBe(true)
    expect(isStepUpBlocked({ reason: 'STEP_UP_MCP_OAUTH_FORBIDDEN' })).toBe(true)
    expect(isStepUpBlocked({ reason: 'STEP_UP_MACHINE_CREDENTIAL_FORBIDDEN' })).toBe(true)
    expect(isStepUpBlocked({ status: 503, reason: 'STEP_UP_UNAVAILABLE' })).toBe(true)
    expect(isStepUpBlocked({ code: 'STEP_UP_REQUIRED' })).toBe(false)
  })

  it('recognizes STEP_UP_UNAVAILABLE old envelope (string code, no reason)', () => {
    const err = {
      status: 503,
      code: 'STEP_UP_UNAVAILABLE',
      message: 'Step-up verification service unavailable'
    }
    expect(isStepUpBlocked(err)).toBe(true)
    expect(isStepUpRequired(err)).toBe(false)
    const t = (key: string) => `i18n:${key}`
    expect(stepUpBlockedMessage(err, t)).toBe('Step-up verification service unavailable')
  })

  it('FD2-9：任意非 REQUIRED 的 STEP_UP_* 前缀都视为阻断', () => {
    expect(isStepUpBlocked({ reason: 'STEP_UP_FUTURE_UNKNOWN' })).toBe(true)
    expect(isStepUpBlocked({ code: 'STEP_UP_SOMETHING_NEW' })).toBe(true)
    expect(isStepUpBlocked({ reason: 'STEP_UP_REQUIRED' })).toBe(false)
    expect(isStepUpBlocked({ reason: 'OTHER' })).toBe(false)
    expect(isStepUpBlocked(new StepUpCancelledError())).toBe(false)
  })

  it('surfaces the block reason marker', () => {
    expect(stepUpBlockReason({ reason: 'STEP_UP_ADMIN_API_KEY_FORBIDDEN' })).toBe('STEP_UP_ADMIN_API_KEY_FORBIDDEN')
    expect(stepUpBlockReason({ code: 'OTHER' })).toBe('')
  })

  it('reads semantic reason when code is numeric HTTP status (round-2 envelope)', () => {
    expect(
      isStepUpRequired({ status: 403, code: 403, reason: 'STEP_UP_REQUIRED' })
    ).toBe(true)
    expect(
      isStepUpBlocked({ status: 403, code: 403, reason: 'STEP_UP_TOTP_NOT_ENABLED' })
    ).toBe(true)
  })

  it('prefers backend message for blocked step-up errors', () => {
    const t = (key: string) => `i18n:${key}`
    expect(
      stepUpBlockedMessage(
        {
          status: 403,
          reason: 'STEP_UP_TOTP_NOT_ENABLED',
          message: '请先在个人设置中开启两步验证（TOTP）后再执行此操作'
        },
        t
      )
    ).toBe('请先在个人设置中开启两步验证（TOTP）后再执行此操作')
    expect(
      stepUpBlockedMessage({ reason: 'STEP_UP_ADMIN_API_KEY_FORBIDDEN' }, t)
    ).toBe('i18n:stepUp.adminApiKeyForbidden')
    expect(stepUpBlockedMessage({ reason: 'STEP_UP_TOTP_NOT_ENABLED' }, t)).toBe(
      'i18n:stepUp.notEnabled'
    )
    expect(stepUpBlockedMessage({ reason: 'STEP_UP_MCP_OAUTH_FORBIDDEN' }, t)).toBe(
      'i18n:stepUp.mcpOauthForbidden'
    )
    expect(
      stepUpBlockedMessage({ reason: 'STEP_UP_MACHINE_CREDENTIAL_FORBIDDEN' }, t)
    ).toBe('i18n:stepUp.machineCredentialForbidden')
    expect(stepUpBlockedMessage({ reason: 'STEP_UP_UNAVAILABLE' }, t)).toBe(
      'i18n:stepUp.unavailable'
    )
    expect(stepUpBlockedMessage({ reason: 'STEP_UP_FUTURE_UNKNOWN' }, t)).toBe(
      'i18n:stepUp.blocked'
    )
  })

  it('does not open TOTP dialog for blocked / unknown STEP_UP_* reasons', async () => {
    const stepUp = useStepUp()
    for (const reason of [
      'STEP_UP_MCP_OAUTH_FORBIDDEN',
      'STEP_UP_MACHINE_CREDENTIAL_FORBIDDEN',
      'STEP_UP_UNAVAILABLE',
      'STEP_UP_FUTURE_UNKNOWN'
    ]) {
      const err = { status: reason === 'STEP_UP_UNAVAILABLE' ? 503 : 403, reason }
      await expect(stepUp.run(async () => { throw err })).rejects.toBe(err)
      expect(stepUp.visible.value).toBe(false)
    }
  })
})

describe('useStepUp concurrent prompts', () => {
  it.each([true, false])('settles every waiter when verification resolves to %s', async (verified) => {
    const stepUp = useStepUp()
    const firstDone = vi.fn()
    const secondDone = vi.fn()
    const first = stepUp.prompt()
    first.then(firstDone)
    stepUp.prompt().then(secondDone)
    if (verified) stepUp.onVerified()
    else stepUp.onCancel()
    await Promise.resolve()
    expect(firstDone).toHaveBeenCalledWith(verified)
    expect(secondDone).toHaveBeenCalledWith(verified)
    expect(stepUp.visible.value).toBe(false)
    const next = stepUp.prompt()
    expect(next).not.toBe(first)
    stepUp.onCancel()
    await expect(next).resolves.toBe(false)
  })
})

describe('useStepUp.run', () => {
  it('returns the action result directly on success', async () => {
    const stepUp = useStepUp()
    const result = await stepUp.run(async () => 42)
    expect(result).toBe(42)
    expect(stepUp.visible.value).toBe(false)
  })

  it('re-throws non-step-up errors without prompting', async () => {
    const stepUp = useStepUp()
    const err = { status: 500, code: 'INTERNAL' }
    await expect(stepUp.run(async () => { throw err })).rejects.toBe(err)
    expect(stepUp.visible.value).toBe(false)
  })

  it('re-throws blocked errors without prompting', async () => {
    const stepUp = useStepUp()
    const err = { status: 403, code: 'STEP_UP_TOTP_NOT_ENABLED' }
    await expect(stepUp.run(async () => { throw err })).rejects.toBe(err)
    expect(stepUp.visible.value).toBe(false)
  })

  it('prompts on STEP_UP_REQUIRED and retries after verification', async () => {
    const stepUp = useStepUp()
    let calls = 0
    const action = async () => {
      calls++
      if (calls === 1) throw { status: 403, code: 'STEP_UP_REQUIRED' }
      return 'ok'
    }
    const promise = stepUp.run(action)
    // The dialog should now be open, awaiting verification (after the first rejection is handled).
    await vi.waitFor(() => expect(stepUp.visible.value).toBe(true))
    stepUp.onVerified()
    await expect(promise).resolves.toBe('ok')
    expect(calls).toBe(2)
    expect(stepUp.visible.value).toBe(false)
  })

  it('throws a cancellation sentinel (not the original error) if the user cancels the prompt', async () => {
    const stepUp = useStepUp()
    const err = { status: 403, code: 'STEP_UP_REQUIRED' }
    const promise = stepUp.run(async () => { throw err })
    await vi.waitFor(() => expect(stepUp.visible.value).toBe(true))
    stepUp.onCancel()
    await expect(promise).rejects.toBeInstanceOf(StepUpCancelledError)
    expect(stepUp.visible.value).toBe(false)
  })

  it('classifies the cancellation sentinel distinctly from step-up errors', () => {
    const cancelled = new StepUpCancelledError()
    expect(isStepUpCancelled(cancelled)).toBe(true)
    expect(isStepUpRequired(cancelled)).toBe(false)
    expect(isStepUpBlocked(cancelled)).toBe(false)
    expect(isStepUpCancelled({ status: 403, code: 'STEP_UP_REQUIRED' })).toBe(false)
  })
})
