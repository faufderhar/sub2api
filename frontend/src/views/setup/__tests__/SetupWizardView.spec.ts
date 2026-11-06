import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import SetupWizardView from '../SetupWizardView.vue'
import enLanding from '@/i18n/locales/en/landing'
import zhLanding from '@/i18n/locales/zh/landing'

const { getSetupStatus, testDatabase, testRedis, install, setSetupToken } = vi.hoisted(() => ({
  getSetupStatus: vi.fn().mockResolvedValue({
    needs_setup: true,
    step: 'database',
    setup_token_required: false
  }),
  testDatabase: vi.fn(),
  testRedis: vi.fn(),
  install: vi.fn(),
  setSetupToken: vi.fn()
}))

vi.mock('@/api/setup', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/setup')>()
  return {
    ...actual,
    getSetupStatus,
    testDatabase,
    testRedis,
    install,
    setSetupToken
  }
})

vi.mock('@/stores', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showWarning: vi.fn()
  })
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() })
}))

function mountWizard() {
  const i18n = createI18n({
    legacy: false,
    locale: 'en',
    fallbackLocale: 'en',
    messages: {
      en: {
        setup: enLanding.setup,
        common: { next: 'Next', back: 'Back' }
      },
      zh: {
        setup: zhLanding.setup,
        common: { next: '下一步', back: '返回' }
      }
    }
  })
  return mount(SetupWizardView, {
    global: {
      plugins: [i18n],
      stubs: {
        Icon: true,
        Toggle: {
          name: 'Toggle',
          props: ['modelValue'],
          template:
            '<button type="button" class="toggle-stub" data-testid="redis-tls-toggle" />'
        },
        Select: true
      }
    }
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function setupState(wrapper: VueWrapper<any>) {
  return (wrapper.vm as any).$.setupState as {
    currentStep: number
    dbConnected: boolean
    formData: { redis: { enable_tls: boolean } }
  }
}

describe('SetupWizardView Redis TLS placement (FD2-13)', () => {
  beforeEach(() => {
    getSetupStatus.mockClear()
  })

  it('does not show Redis TLS toggle on the database step', async () => {
    const wrapper = mountWizard()
    await flushPromises()
    expect(setupState(wrapper).currentStep).toBe(0)
    expect(wrapper.text()).toContain(enLanding.setup.database.title)
    expect(wrapper.text()).not.toContain(enLanding.setup.redis.enableTls)
    expect(wrapper.findAll('[data-testid="redis-tls-toggle"]')).toHaveLength(0)
    // Payload field remains on the install form model (not removed by UI fix)
    expect(setupState(wrapper).formData.redis.enable_tls).toBe(false)
    wrapper.unmount()
  })

  it('shows Redis TLS toggle only on the Redis step', async () => {
    const wrapper = mountWizard()
    await flushPromises()
    const state = setupState(wrapper)
    state.dbConnected = true
    state.currentStep = 1
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain(enLanding.setup.redis.title)
    expect(wrapper.text()).toContain(enLanding.setup.redis.enableTls)
    expect(wrapper.findAll('[data-testid="redis-tls-toggle"]')).toHaveLength(1)
    expect(state.formData.redis.enable_tls).toBe(false)
    wrapper.unmount()
  })
})
