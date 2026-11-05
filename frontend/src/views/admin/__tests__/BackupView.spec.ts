import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

import BackupView from '../BackupView.vue'

const {
  getS3Config,
  getImageStorageConfig,
  getSchedule,
  updateSchedule,
  deleteBackup,
  listBackups,
  getDownloadURL,
  updateS3Config,
  updateImageStorageConfig,
  testS3Connection,
  testImageStorageConnection,
  createBackupApi,
  restoreBackupApi,
  stepUpRun,
  showError,
  showSuccess,
  showWarning,
  isStepUpBlocked,
  isStepUpCancelled,
  stepUpBlockedMessage,
} = vi.hoisted(() => ({
  getS3Config: vi.fn(),
  getImageStorageConfig: vi.fn(),
  getSchedule: vi.fn(),
  updateSchedule: vi.fn(),
  deleteBackup: vi.fn(),
  listBackups: vi.fn(),
  getDownloadURL: vi.fn(),
  updateS3Config: vi.fn(),
  updateImageStorageConfig: vi.fn(),
  testS3Connection: vi.fn(),
  testImageStorageConnection: vi.fn(),
  createBackupApi: vi.fn(),
  restoreBackupApi: vi.fn(),
  stepUpRun: vi.fn(async (fn: () => unknown) => fn()),
  showError: vi.fn(),
  showSuccess: vi.fn(),
  showWarning: vi.fn(),
  isStepUpBlocked: vi.fn(() => false),
  isStepUpCancelled: vi.fn(() => false),
  stepUpBlockedMessage: vi.fn((err: { message?: string }) => err?.message || 'step-up-blocked'),
}))

vi.mock('@/api', () => ({
  adminAPI: {
    backup: {
      getS3Config,
      updateS3Config,
      testS3Connection,
      getImageStorageConfig,
      updateImageStorageConfig,
      testImageStorageConnection,
      getSchedule,
      updateSchedule,
      createBackup: createBackupApi,
      listBackups,
      getBackup: vi.fn(),
      deleteBackup,
      getDownloadURL,
      restoreBackup: restoreBackupApi,
    },
  },
}))

vi.mock('@/stores', () => ({
  useAppStore: () => ({
    showError,
    showSuccess,
    showWarning,
  }),
}))

vi.mock('@/composables/useStepUp', () => ({
  useStepUp: () => ({
    run: stepUpRun,
    visible: { value: false },
    blockedReason: { value: '' },
    prompt: vi.fn(),
    onVerified: vi.fn(),
    onCancel: vi.fn(),
  }),
  isStepUpBlocked: (...args: unknown[]) => isStepUpBlocked(...args),
  isStepUpCancelled: (...args: unknown[]) => isStepUpCancelled(...args),
  stepUpBlockedMessage: (...args: unknown[]) => stepUpBlockedMessage(...args),
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string, params?: Record<string, unknown>) =>
      params?.index !== undefined ? `${key}:${params.index}` : params?.day !== undefined ? `${key}:${params.day}` : key,
  }),
}))

const baseRecord = (id: string, parts?: unknown[]) => ({
  id,
  status: 'completed',
  backup_type: 'postgres',
  file_name: `${id}.sql.gz`,
  s3_key: `backups/${id}.sql.gz`,
  parts,
  size_bytes: 10,
  triggered_by: 'manual',
  started_at: '2026-08-09T00:00:00Z',
})

const wrappers: ReturnType<typeof mount>[] = []

function mountBackupView() {
  const wrapper = mount(BackupView, {
    global: {
      stubs: {
        TotpStepUpDialog: true,
      },
    },
  })
  wrappers.push(wrapper)
  return wrapper
}

describe('admin BackupView', () => {
  beforeEach(() => {
    getS3Config.mockResolvedValue({})
    getImageStorageConfig.mockResolvedValue({ config: {}, secret_configured: false })
    getSchedule.mockResolvedValue({ enabled: false, cron_expr: '', retain_days: 14, retain_count: 10 })
    updateSchedule.mockReset().mockResolvedValue({})
    deleteBackup.mockReset().mockResolvedValue(undefined)
    listBackups.mockResolvedValue({ items: [] })
    getDownloadURL.mockReset()
    updateS3Config.mockReset().mockResolvedValue({})
    updateImageStorageConfig.mockReset().mockResolvedValue({})
    testS3Connection.mockReset().mockResolvedValue({ ok: true, message: 'ok' })
    testImageStorageConnection.mockReset().mockResolvedValue({ ok: true, message: 'ok' })
    createBackupApi.mockReset().mockResolvedValue(baseRecord('new'))
    restoreBackupApi.mockReset().mockResolvedValue(baseRecord('restored'))
    stepUpRun.mockReset().mockImplementation(async (fn: () => unknown) => fn())
    showError.mockReset()
    showSuccess.mockReset()
    showWarning.mockReset()
    isStepUpBlocked.mockReset().mockReturnValue(false)
    isStepUpCancelled.mockReset().mockReturnValue(false)
    stepUpBlockedMessage.mockReset().mockImplementation(
      (err: { message?: string }) => err?.message || 'step-up-blocked',
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  afterEach(() => {
    wrappers.splice(0).forEach(wrapper => wrapper.unmount())
    vi.restoreAllMocks()
    document.body.innerHTML = ''
  })

  it.each(['backup', 'restore'])('does not resume %s polling after navigation during initial loading', async (operation) => {
    vi.useFakeTimers()
    let finish!: (value: object) => void
    listBackups.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const wrapper = mountBackupView()
    try {
      await flushPromises()
      wrapper.unmount()
      finish({ items: [{ ...baseRecord('pending'),
        status: operation === 'backup' ? 'running' : 'completed',
        restore_status: operation === 'restore' ? 'running' : undefined,
      }] })
      await flushPromises()
      expect(vi.getTimerCount()).toBe(0)
    } finally {
      wrapper.unmount()
      vi.clearAllTimers()
      vi.useRealTimers()
    }
  })

  it('显示分卷数并在下载时列出每个分卷链接', async () => {
    listBackups.mockResolvedValue({
      items: [baseRecord('split', [{ index: 1 }, { index: 2 }, { index: 3 }])],
    })
    getDownloadURL.mockResolvedValue({
      parts: [
        { index: 1, size_bytes: 5, url: 'https://example.test/part-1' },
        { index: 2, size_bytes: 6, url: 'https://example.test/part-2' },
        { index: 3, size_bytes: 7, url: 'https://example.test/part-3' },
      ],
    })

    const wrapper = mountBackupView()
    await flushPromises()

    expect(wrapper.text()).toContain('3')
    const downloadButton = wrapper.findAll('button').find(button =>
      button.text().includes('admin.backup.actions.download'),
    )
    expect(downloadButton).toBeDefined()
    await downloadButton!.trigger('click')
    await flushPromises()

    expect(document.body.textContent).toContain('admin.backup.actions.partLabel:1')
    expect(document.body.textContent).toContain('admin.backup.actions.partLabel:3')
    expect(document.body.querySelector('a[href="https://example.test/part-2"]')).not.toBeNull()
  })

  it('旧单文件记录仍使用单个下载地址', async () => {
    listBackups.mockResolvedValue({ items: [baseRecord('legacy')] })
    getDownloadURL.mockResolvedValue({ url: 'https://example.test/legacy.sql.gz' })

    const wrapper = mountBackupView()
    await flushPromises()
    const downloadButton = wrapper.findAll('button').find(button =>
      button.text().includes('admin.backup.actions.download'),
    )
    await downloadButton!.trigger('click')
    await flushPromises()

    expect(getDownloadURL).toHaveBeenCalledWith('legacy')
    expect(document.body.textContent).not.toContain('admin.backup.actions.downloadParts')
  })

  it('运行中的备份不显示删除入口', async () => {
    listBackups.mockResolvedValue({
      items: [{ ...baseRecord('running'), status: 'running', progress: 'uploading' }],
    })

    const wrapper = mountBackupView()
    await flushPromises()

    expect(wrapper.find('tbody tr td:nth-child(5)').text()).toBe('-')
    expect(wrapper.findAll('button').some(button => button.text() === 'common.delete')).toBe(false)
  })

  it('兼容旧配置并保留 0 值，不自动启用月度归档', async () => {
    getSchedule.mockResolvedValue({ enabled: true, cron_expr: '0 4 * * *', retain_days: 0, retain_count: 0 })
    const wrapper = mountBackupView()
    await flushPromises()
    expect((wrapper.get('[data-testid="backup-retain-days"]').element as HTMLInputElement).value).toBe('0')
    expect((wrapper.get('[data-testid="backup-retain-count"]').element as HTMLInputElement).value).toBe('0')
    expect((wrapper.get('[data-testid="archive-enabled"]').element as HTMLInputElement).checked).toBe(false)
    await wrapper.get('[data-testid="backup-schedule"] .btn-primary').trigger('click')
    await flushPromises()
    expect(updateSchedule).toHaveBeenCalledWith(expect.objectContaining({ retain_days: 0, retain_count: 0, monthly_archive: expect.objectContaining({ enabled: false }) }))
  })

  it('多选日期，手填份数；永久保留隐藏数量并在取消后恢复', async () => {
    const wrapper = mountBackupView()
    await flushPromises()
    await wrapper.get('[data-testid="archive-enabled"]').setValue(true)
    await wrapper.get('#backup-archive-dates').trigger('click')
    await wrapper.get('#backup-archive-options input[value="15"]').setValue(true)
    await wrapper.get('#backup-archive-options input[value="last"]').setValue(true)
    expect(wrapper.get('#backup-archive-dates').attributes('aria-expanded')).toBe('true')
    expect(wrapper.find('[data-testid="archive-count"]').exists()).toBe(false)
    await wrapper.get('[data-testid="archive-forever"]').setValue(false)
    await wrapper.get('[data-testid="archive-count"]').setValue(17)
    await wrapper.get('[data-testid="archive-forever"]').setValue(true)
    expect(wrapper.find('[data-testid="archive-count"]').exists()).toBe(false)
    expect(wrapper.findComponent({ name: 'BackupArchiveSettings' }).text()).not.toContain('admin.backup.archive.copies')
    await wrapper.get('[data-testid="archive-forever"]').setValue(false)
    expect((wrapper.get('[data-testid="archive-count"]').element as HTMLInputElement).value).toBe('17')
    await wrapper.get('[data-testid="backup-schedule"] .btn-primary').trigger('click')
    await flushPromises()
    expect(updateSchedule).toHaveBeenLastCalledWith(expect.objectContaining({ monthly_archive: { enabled: true, days: [1, 15], include_month_end: true, retain_count: 17 } }))
    await wrapper.get('[data-testid="archive-forever"]').setValue(true)
    await wrapper.get('[data-testid="backup-schedule"] .btn-primary').trigger('click')
    expect(updateSchedule).toHaveBeenLastCalledWith(expect.objectContaining({ monthly_archive: expect.objectContaining({ retain_count: 0 }) }))
  })

  it('空日期和非法份数不可保存，输入 0 不会误选永久保留', async () => {
    const wrapper = mountBackupView()
    await flushPromises()
    await wrapper.get('[data-testid="archive-enabled"]').setValue(true)
    await wrapper.get('#backup-archive-dates').trigger('click')
    await wrapper.get('#backup-archive-options input[value="1"]').setValue(false)
    const save = wrapper.get('[data-testid="backup-schedule"] .btn-primary')
    expect(save.attributes('disabled')).toBeDefined()
    await wrapper.get('#backup-archive-options input[value="15"]').setValue(true)
    await wrapper.get('[data-testid="archive-forever"]').setValue(false)
    for (const value of ['0', '-1', '1.5', '']) {
      await wrapper.get('[data-testid="archive-count"]').setValue(value)
      expect(save.attributes('disabled')).toBeDefined()
      expect((wrapper.get('[data-testid="archive-forever"]').element as HTMLInputElement).checked).toBe(false)
    }
    await save.trigger('click')
    expect(updateSchedule).not.toHaveBeenCalled()
  })

  it('关闭月度归档后不提交隐藏的归档参数，重新启用时保留编辑值', async () => {
    getSchedule.mockResolvedValue({ enabled: true, cron_expr: '0 4 * * *', retain_days: 14, retain_count: 10,
      monthly_archive: { enabled: true, days: [1, 15], include_month_end: false, retain_count: 12 } })
    const wrapper = mountBackupView()
    await flushPromises()
    await wrapper.get('[data-testid="archive-count"]').setValue(1)
    await wrapper.get('[data-testid="archive-enabled"]').setValue(false)
    expect(wrapper.find('[data-testid="archive-count"]').exists()).toBe(false)
    const save = wrapper.get('[data-testid="backup-schedule"] .btn-primary')
    await save.trigger('click')
    await flushPromises()
    expect(updateSchedule).toHaveBeenLastCalledWith(expect.objectContaining({ monthly_archive: { enabled: false, days: [1, 15], include_month_end: false, retain_count: 12 } }))
    await wrapper.get('[data-testid="archive-enabled"]').setValue(true)
    expect((wrapper.get('[data-testid="archive-count"]').element as HTMLInputElement).value).toBe('1')
    // A hidden invalid count neither blocks saving nor reaches the request.
    await wrapper.get('[data-testid="archive-count"]').setValue('')
    expect(save.attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="archive-enabled"]').setValue(false)
    expect(save.attributes('disabled')).toBeUndefined()
    await save.trigger('click')
    await flushPromises()
    expect(updateSchedule).toHaveBeenLastCalledWith(expect.objectContaining({ monthly_archive: { enabled: false, days: [1, 15], include_month_end: false, retain_count: 12 } }))
    await wrapper.get('[data-testid="archive-enabled"]').setValue(true)
    await wrapper.get('[data-testid="archive-count"]').setValue(1)
    await save.trigger('click')
    await flushPromises()
    expect(updateSchedule).toHaveBeenLastCalledWith(expect.objectContaining({ monthly_archive: { enabled: true, days: [1, 15], include_month_end: false, retain_count: 1 } }))
  })

  it('加载归档设置并支持键盘关闭日期选择器', async () => {
    getSchedule.mockResolvedValue({ enabled: true, cron_expr: '0 4 * * *', retain_days: 14, retain_count: 10,
      monthly_archive: { enabled: true, days: [1, 15], include_month_end: true, retain_count: 23 } })
    const wrapper = mountBackupView()
    await flushPromises()
    expect((wrapper.get('[data-testid="archive-count"]').element as HTMLInputElement).value).toBe('23')
    await wrapper.get('#backup-archive-dates').trigger('keydown', { key: 'ArrowDown' })
    await flushPromises()
    expect(wrapper.find('#backup-archive-options').exists()).toBe(true)
    expect((wrapper.get('#backup-archive-options input[value="15"]').element as HTMLInputElement).checked).toBe(true)
    await wrapper.get('#backup-archive-options').trigger('keydown', { key: 'Escape' })
    expect(wrapper.find('#backup-archive-options').exists()).toBe(false)
  })

  it('归档删除需要单独确认，有限归档不会显示永不过期', async () => {
    listBackups.mockResolvedValue({ items: [{ ...baseRecord('archived'), monthly_archive: { dates: ['2026-09-01', '2026-09-15'], retain_count: 12 } }] })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    const wrapper = mountBackupView()
    await flushPromises()
    expect(wrapper.text()).toContain('admin.backup.archive.badge')
    expect(wrapper.get('tbody tr td:nth-child(6)').text()).toBe('admin.backup.archive.retainLatest')
    const button = wrapper.findAll('button').find(button => button.text() === 'common.delete')!
    await button.trigger('click')
    expect(confirm).toHaveBeenCalledWith('admin.backup.archive.deleteConfirm')
    expect(deleteBackup).not.toHaveBeenCalled()
    confirm.mockReturnValue(true)
    await button.trigger('click')
    await flushPromises()
    expect(deleteBackup).toHaveBeenCalledWith('archived', true)
  })
})


describe('admin BackupView step-up (F-4 M-7)', () => {
  beforeEach(() => {
    getS3Config.mockResolvedValue({})
    getImageStorageConfig.mockResolvedValue({ config: {}, secret_configured: false })
    getSchedule.mockResolvedValue({ enabled: false, cron_expr: '', retain_days: 14, retain_count: 10 })
    listBackups.mockResolvedValue({ items: [] })
    updateS3Config.mockReset().mockResolvedValue({})
    updateImageStorageConfig.mockReset().mockResolvedValue({})
    testS3Connection.mockReset().mockResolvedValue({ ok: true })
    testImageStorageConnection.mockReset().mockResolvedValue({ ok: true })
    createBackupApi.mockReset().mockResolvedValue(baseRecord('new'))
    restoreBackupApi.mockReset().mockResolvedValue(baseRecord('legacy'))
    getDownloadURL.mockReset().mockResolvedValue({ url: 'https://example.test/file.sql.gz' })
    stepUpRun.mockReset().mockImplementation(async (fn: () => unknown) => fn())
    showError.mockReset()
    isStepUpBlocked.mockReset().mockReturnValue(false)
    isStepUpCancelled.mockReset().mockReturnValue(false)
    stepUpBlockedMessage.mockReset().mockImplementation(
      (err: { message?: string }) => err?.message || 'step-up-blocked',
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  afterEach(() => {
    wrappers.splice(0).forEach(wrapper => wrapper.unmount())
    vi.restoreAllMocks()
    document.body.innerHTML = ''
  })

  it('PUT s3-config 保存走 stepUp.run', async () => {
    const wrapper = mountBackupView()
    await flushPromises()
    stepUpRun.mockClear()
    await wrapper.get('[data-testid="backup-s3-save"]').trigger('click')
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledTimes(1)
    expect(updateS3Config).toHaveBeenCalled()
  })

  it('PUT image-storage 保存走 stepUp.run', async () => {
    const wrapper = mountBackupView()
    await flushPromises()
    stepUpRun.mockClear()
    await wrapper.get('[data-testid="backup-image-storage-save"]').trigger('click')
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledTimes(1)
    expect(updateImageStorageConfig).toHaveBeenCalled()
  })

  it('创建备份走 stepUp.run', async () => {
    const wrapper = mountBackupView()
    await flushPromises()
    stepUpRun.mockClear()
    await wrapper.get('[data-testid="backup-create"]').trigger('click')
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledTimes(1)
    expect(createBackupApi).toHaveBeenCalled()
  })

  it('下载 download-url 走 stepUp.run', async () => {
    listBackups.mockResolvedValue({ items: [baseRecord('legacy')] })
    const wrapper = mountBackupView()
    await flushPromises()
    stepUpRun.mockClear()
    const downloadButton = wrapper.findAll('button').find(button =>
      button.text().includes('admin.backup.actions.download'),
    )
    await downloadButton!.trigger('click')
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledTimes(1)
    expect(getDownloadURL).toHaveBeenCalledWith('legacy')
  })

  it('恢复备份走 stepUp.run', async () => {
    listBackups.mockResolvedValue({ items: [baseRecord('legacy')] })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.spyOn(window, 'prompt').mockReturnValue('secret')
    const wrapper = mountBackupView()
    await flushPromises()
    stepUpRun.mockClear()
    const restoreButton = wrapper.findAll('button').find(button =>
      button.text().includes('admin.backup.actions.restore'),
    )
    await restoreButton!.trigger('click')
    await flushPromises()
    expect(stepUpRun).toHaveBeenCalledTimes(1)
    expect(restoreBackupApi).toHaveBeenCalledWith('legacy', 'secret')
  })

  it('S3/图片「测试连接」不走 stepUp（后端未挂门控）', async () => {
    const wrapper = mountBackupView()
    await flushPromises()
    stepUpRun.mockClear()
    await wrapper.get('[data-testid="backup-s3-test"]').trigger('click')
    await wrapper.get('[data-testid="backup-image-storage-test"]').trigger('click')
    await flushPromises()
    expect(stepUpRun).not.toHaveBeenCalled()
    expect(testS3Connection).toHaveBeenCalled()
    expect(testImageStorageConnection).toHaveBeenCalled()
  })

  it.each([
    ['STEP_UP_TOTP_NOT_ENABLED', '请先开启 TOTP'],
    ['STEP_UP_ADMIN_API_KEY_FORBIDDEN', '机器凭证不可用'],
  ])('S3 保存处理阻塞错误 %s', async (reason, message) => {
    const err = { status: 403, code: 403, reason, message }
    updateS3Config.mockRejectedValue(err)
    isStepUpBlocked.mockReturnValue(true)
    stepUpBlockedMessage.mockReturnValue(message)
    const wrapper = mountBackupView()
    await flushPromises()
    await wrapper.get('[data-testid="backup-s3-save"]').trigger('click')
    await flushPromises()
    expect(isStepUpBlocked).toHaveBeenCalledWith(err)
    expect(stepUpBlockedMessage).toHaveBeenCalledWith(err, expect.any(Function))
    expect(showError).toHaveBeenCalledWith(message)
  })

  it('图片存储保存处理 STEP_UP_TOTP_NOT_ENABLED', async () => {
    const err = {
      status: 403,
      reason: 'STEP_UP_TOTP_NOT_ENABLED',
      message: '请先在个人设置中开启两步验证（TOTP）后再执行此操作',
    }
    updateImageStorageConfig.mockRejectedValue(err)
    isStepUpBlocked.mockReturnValue(true)
    stepUpBlockedMessage.mockReturnValue(err.message)
    const wrapper = mountBackupView()
    await flushPromises()
    await wrapper.get('[data-testid="backup-image-storage-save"]').trigger('click')
    await flushPromises()
    expect(showError).toHaveBeenCalledWith(err.message)
  })
})
