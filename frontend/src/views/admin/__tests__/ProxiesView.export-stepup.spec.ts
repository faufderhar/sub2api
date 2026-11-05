import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, shallowMount } from '@vue/test-utils'
import ProxiesView from '../ProxiesView.vue'

const { exportData, listProxies, getAllWithCount, stepUpRun } = vi.hoisted(() => ({
  exportData: vi.fn(),
  listProxies: vi.fn(),
  getAllWithCount: vi.fn(),
  stepUpRun: vi.fn(async (fn: () => unknown) => fn())
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    proxies: {
      list: listProxies,
      getAllWithCount,
      exportData
    }
  }
}))

vi.mock('@/composables/useStepUp', () => ({
  useStepUp: () => ({
    run: stepUpRun,
    visible: { value: false },
    blockedReason: { value: '' },
    prompt: vi.fn(),
    onVerified: vi.fn(),
    onCancel: vi.fn()
  }),
  isStepUpCancelled: () => false,
  isStepUpBlocked: (err: { reason?: string }) =>
    typeof err?.reason === 'string' &&
    err.reason.startsWith('STEP_UP_') &&
    err.reason !== 'STEP_UP_REQUIRED',
  stepUpBlockedMessage: (err: { message?: string }) => err?.message || 'step-up-blocked'
}))

const showError = vi.fn()
const showSuccess = vi.fn()
vi.mock('@/stores/app', () => ({
  useAppStore: () => ({ showError, showSuccess })
}))
vi.mock('vue-i18n', async () => ({
  ...(await vi.importActual<typeof import('vue-i18n')>('vue-i18n')),
  useI18n: () => ({ t: (key: string) => key })
}))

const mountView = () =>
  shallowMount(ProxiesView, {
    global: {
      stubs: {
        AppLayout: { template: '<div><slot /></div>' },
        TablePageLayout: {
          template:
            '<div><slot name="filters" /><slot name="table" /><slot name="pagination" /><slot name="actions" /></div>'
        },
        DataTable: { template: '<div />' },
        Pagination: { template: '<div />' },
        Select: { template: '<div />' },
        ConfirmDialog: {
          props: ['show'],
          emits: ['confirm'],
          template:
            '<button v-if="show" data-test="export-confirm" @click="$emit(\'confirm\')" />'
        },
        TotpStepUpDialog: true
      }
    }
  })

describe('ProxiesView export step-up (FD2-1)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getAllWithCount.mockResolvedValue([])
    listProxies.mockResolvedValue({ items: [], total: 0, pages: 0 })
    exportData.mockResolvedValue({ proxies: [] })
    stepUpRun.mockImplementation(async (fn: () => unknown) => fn())
    // jsdom URL helpers used by download path
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:mock'),
      revokeObjectURL: vi.fn()
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('wraps exportData with stepUp.run', async () => {
    const wrapper = mountView()
    await flushPromises()
    ;(wrapper.vm as any).showExportDataDialog = true
    await flushPromises()
    await (wrapper.vm as any).handleExportData()
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledOnce()
    expect(exportData).toHaveBeenCalledOnce()
    expect(showSuccess).toHaveBeenCalled()
    wrapper.unmount()
  })

  it('shows blocked message without treating cancel as error', async () => {
    stepUpRun.mockRejectedValueOnce({
      reason: 'STEP_UP_MCP_OAUTH_FORBIDDEN',
      message: 'mcp blocked'
    })
    const wrapper = mountView()
    await flushPromises()
    await (wrapper.vm as any).handleExportData()
    await flushPromises()
    expect(showError).toHaveBeenCalledWith('mcp blocked')
    expect(showSuccess).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
