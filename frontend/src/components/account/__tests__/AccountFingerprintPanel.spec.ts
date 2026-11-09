import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent } from 'vue'

const { getFingerprint, regenerateFingerprint, showError, showSuccess, stepUpRun } = vi.hoisted(() => ({
  getFingerprint: vi.fn(),
  regenerateFingerprint: vi.fn(),
  showError: vi.fn(),
  showSuccess: vi.fn(),
  stepUpRun: vi.fn(async (fn: () => unknown) => fn())
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    accounts: { getFingerprint, regenerateFingerprint }
  }
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({ showError, showSuccess })
}))

vi.mock('@/composables/useStepUp', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/composables/useStepUp')>()
  return {
    ...actual,
    useStepUp: () => ({ run: stepUpRun })
  }
})

vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key
    })
  }
})

import AccountFingerprintPanel from '../AccountFingerprintPanel.vue'

const applicable = {
  applicable: true,
  regenerable: true,
  generation: 1,
  source: 'created' as const,
  user_agent: 'claude-cli/2.1.78 (external, cli)',
  os: 'linux',
  arch: 'x64',
  runtime: 'node',
  runtime_version: 'v24.3.0',
  client_id_prefix: 'a1b2c3d4',
  tls_profile_id: 3,
  tls_profile_name: 'Node.js 24 / Linux',
  tls_binding: 'auto' as const,
  updated_at: '2026-11-07T14:00:00Z',
  account_uuid_present: true,
  account_uuid_changed: false,
  passthrough_user_id: false,
  conflict: false
}

function mountPanel() {
  return mount(AccountFingerprintPanel, {
    props: { accountId: 12 },
    global: {
      stubs: {
        TotpStepUpDialog: defineComponent({ template: '<div />' })
      }
    }
  })
}

describe('AccountFingerprintPanel (R3-FP)', () => {
  beforeEach(() => {
    getFingerprint.mockReset()
    regenerateFingerprint.mockReset()
    showError.mockReset()
    showSuccess.mockReset()
    stepUpRun.mockClear()
    getFingerprint.mockResolvedValue({ applicable: false, regenerable: false })
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111')
  })

  it('shows an explanation when the account is not applicable', async () => {
    const wrapper = mountPanel()
    await flushPromises()
    expect(getFingerprint).toHaveBeenCalledWith(12)
    expect(wrapper.get('[data-testid="fingerprint-not-applicable"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="fingerprint-regenerate"]').exists()).toBe(false)
  })

  it('renders the summary and warnings', async () => {
    getFingerprint.mockResolvedValue({
      ...applicable,
      conflict: true,
      passthrough_user_id: true,
      account_uuid_changed: true
    })
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.get('[data-testid="fingerprint-summary"]').text()).toContain('a1b2c3d4')
    expect(wrapper.get('[data-testid="fingerprint-conflict"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="fingerprint-passthrough"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="fingerprint-uuid-changed"]').exists()).toBe(true)
  })

  it('hides regenerate when regenerable is false', async () => {
    getFingerprint.mockResolvedValue({ ...applicable, regenerable: false })
    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.find('[data-testid="fingerprint-regenerate"]').exists()).toBe(false)
  })

  it('requires a second confirmation that mentions a device change and then regenerates via step-up', async () => {
    getFingerprint.mockResolvedValue(applicable)
    regenerateFingerprint.mockResolvedValue({ ...applicable, generation: 2, source: 'regenerated' })
    const wrapper = mountPanel()
    await flushPromises()
    await wrapper.get('[data-testid="fingerprint-regenerate"]').trigger('click')
    expect(regenerateFingerprint).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="fingerprint-regenerate-warning"]').text()).toBe(
      'admin.accounts.fingerprint.regenerateWarning'
    )
    await wrapper.get('[data-testid="fingerprint-regenerate-cancel"]').trigger('click')
    expect(regenerateFingerprint).not.toHaveBeenCalled()

    await wrapper.get('[data-testid="fingerprint-regenerate"]').trigger('click')
    await wrapper.get('[data-testid="fingerprint-regenerate-confirm"]').trigger('click')
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledTimes(1)
    expect(regenerateFingerprint).toHaveBeenCalledWith(
      12,
      { confirm: true, expected_generation: 1 },
      { idempotencyKey: '11111111-1111-4111-8111-111111111111' }
    )
    expect(showSuccess).toHaveBeenCalledWith('admin.accounts.fingerprint.regenerateSuccess')
  })

  it('re-GETs the summary on generation conflict instead of blindly retrying', async () => {
    getFingerprint.mockResolvedValue(applicable)
    regenerateFingerprint.mockRejectedValue({ reason: 'FINGERPRINT_GENERATION_CONFLICT' })
    const wrapper = mountPanel()
    await flushPromises()
    getFingerprint.mockResolvedValue({ ...applicable, generation: 2, source: 'regenerated' })
    await wrapper.get('[data-testid="fingerprint-regenerate"]').trigger('click')
    await wrapper.get('[data-testid="fingerprint-regenerate-confirm"]').trigger('click')
    await flushPromises()
    expect(regenerateFingerprint).toHaveBeenCalledTimes(1)
    expect(getFingerprint).toHaveBeenCalledTimes(2)
    expect(showError).toHaveBeenCalledWith('admin.accounts.fingerprint.generationConflict')
  })
})
