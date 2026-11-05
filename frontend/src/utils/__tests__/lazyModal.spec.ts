import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed, defineComponent, h, nextTick, ref, watch } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'

const showError = vi.fn()
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showError }) }))

import { lazyModal, isChunkLoadError } from '../lazyModal'

// 模拟一个“只在 show 由 false 变为 true 时才初始化”的弹窗（与 CreateAccountModal 等一致）
const opened = vi.fn()
const RealModal = defineComponent({
  name: 'RealModal',
  props: { show: Boolean, title: String },
  emits: ['close'],
  setup(props, { emit, slots }) {
    watch(() => props.show, (v) => { if (v) opened(props.title) })
    return () => props.show
      ? h('div', { 'data-test': 'modal' }, [props.title, slots.default?.(), h('button', { onClick: () => emit('close') }, 'x')])
      : null
  }
})

describe('lazyModal', () => {
  it('首次打开前不加载，打开后照常触发 show watcher，并透传 props/事件/插槽', async () => {
    opened.mockReset()
    const loader = vi.fn(() => Promise.resolve({ default: RealModal }))
    const Lazy = lazyModal(loader)
    const show = ref(false)
    const onClose = vi.fn(() => { show.value = false })
    const wrapper = mount(defineComponent({
      setup: () => () => h(Lazy as any, { show: show.value, title: 'hello', onClose }, { default: () => 'slot-content' })
    }))
    await flushPromises()
    expect(loader).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="modal"]').exists()).toBe(false)

    show.value = true
    await flushPromises(); await nextTick()
    expect(loader).toHaveBeenCalledTimes(1)
    expect(opened).toHaveBeenCalledWith('hello')
    expect(wrapper.get('[data-test="modal"]').text()).toContain('slot-content')

    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(onClose).toHaveBeenCalled()
    expect(wrapper.find('[data-test="modal"]').exists()).toBe(false)

    show.value = true
    await flushPromises(); await nextTick()
    expect(loader).toHaveBeenCalledTimes(1)
    expect(opened).toHaveBeenCalledTimes(2)
  })

  it('加载失败时不抛到渲染层，下次打开会重试', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    let fail = true
    const loader = vi.fn(() => fail ? Promise.reject(new Error('chunk 404')) : Promise.resolve({ default: RealModal }))
    const Lazy = lazyModal(loader)
    const show = ref(true)
    const wrapper = mount(defineComponent({ setup: () => () => h(Lazy as any, { show: show.value, title: 't' }) }))
    await flushPromises()
    expect(wrapper.find('[data-test="modal"]').exists()).toBe(false)
    expect(err).toHaveBeenCalled()
    show.value = false; await flushPromises()
    fail = false
    show.value = true
    await flushPromises(); await nextTick()
    expect(loader).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-test="modal"]').exists()).toBe(true)
    err.mockRestore()
  })

  describe('D-1：加载失败时复位父组件 open 状态并提示', () => {
    let reload: ReturnType<typeof vi.fn>
    const originalLocation = window.location
    beforeEach(() => {
      showError.mockReset()
      sessionStorage.clear()
      reload = vi.fn()
      Object.defineProperty(window, 'location', { configurable: true, value: { ...originalLocation, reload } })
      vi.spyOn(console, 'error').mockImplementation(() => {})
      vi.spyOn(console, 'warn').mockImplementation(() => {})
    })
    afterEach(() => {
      Object.defineProperty(window, 'location', { configurable: true, value: originalLocation })
      vi.restoreAllMocks()
    })

    // 模拟 AccountsView：按钮把 showCreate 置为 true，@close 复位；isAnyModalOpen 决定是否暂停自动刷新
    const mountParent = (loader: () => Promise<{ default: any }>) => {
      const Lazy = lazyModal(loader)
      const showCreate = ref(false)
      const isAnyModalOpen = computed(() => showCreate.value)
      const wrapper = mount(defineComponent({
        setup: () => () => h('div', [
          h('button', { 'data-test': 'open', onClick: () => { showCreate.value = true } }, 'open'),
          h(Lazy as any, { show: showCreate.value, title: 'create', onClose: () => { showCreate.value = false } })
        ])
      }))
      return { wrapper, showCreate, isAnyModalOpen }
    }

    it('普通加载错误：emit close 让父组件复位、弹 toast；父组件不手动复位也能再次点击重试成功', async () => {
      let fail = true
      const loader = vi.fn(() => fail ? Promise.reject(new Error('network down')) : Promise.resolve({ default: RealModal }))
      const { wrapper, showCreate, isAnyModalOpen } = mountParent(loader)

      await wrapper.get('[data-test="open"]').trigger('click')
      await flushPromises()
      expect(loader).toHaveBeenCalledTimes(1)
      expect(showCreate.value).toBe(false)
      expect(isAnyModalOpen.value).toBe(false)
      expect(showError).toHaveBeenCalledWith('common.componentLoadFailed')
      expect(reload).not.toHaveBeenCalled()

      fail = false
      await wrapper.get('[data-test="open"]').trigger('click')
      await flushPromises(); await nextTick()
      expect(loader).toHaveBeenCalledTimes(2)
      expect(wrapper.find('[data-test="modal"]').exists()).toBe(true)
      expect(isAnyModalOpen.value).toBe(true)
    })

    it('chunk 加载错误：整页刷新一次；10 秒内再次失败不再刷新，改为 toast，且仍可重试', async () => {
      let fail = true
      const chunkErr = () => new TypeError('Failed to fetch dynamically imported module: http://x/assets/CreateAccountModal-abc.js')
      const loader = vi.fn(() => fail ? Promise.reject(chunkErr()) : Promise.resolve({ default: RealModal }))
      const { wrapper, showCreate } = mountParent(loader)

      await wrapper.get('[data-test="open"]').trigger('click')
      await flushPromises()
      expect(reload).toHaveBeenCalledTimes(1)
      expect(showError).not.toHaveBeenCalled()
      expect(showCreate.value).toBe(false)
      expect(sessionStorage.getItem('chunk_reload_attempted')).not.toBeNull()

      await wrapper.get('[data-test="open"]').trigger('click')
      await flushPromises()
      expect(reload).toHaveBeenCalledTimes(1)
      expect(showError).toHaveBeenCalledWith('common.componentLoadFailed')
      expect(showCreate.value).toBe(false)

      fail = false
      await wrapper.get('[data-test="open"]').trigger('click')
      await flushPromises(); await nextTick()
      expect(loader).toHaveBeenCalledTimes(3)
      expect(wrapper.find('[data-test="modal"]').exists()).toBe(true)
    })

    it('isChunkLoadError 识别各浏览器的动态 import 失败信息', () => {
      expect(isChunkLoadError(new TypeError('Failed to fetch dynamically imported module: x'))).toBe(true)
      expect(isChunkLoadError(new TypeError('error loading dynamically imported module: x'))).toBe(true)
      expect(isChunkLoadError(new TypeError('Importing a module script failed.'))).toBe(true)
      expect(isChunkLoadError(new Error('Loading CSS chunk 1 failed'))).toBe(true)
      const named = new Error('x'); named.name = 'ChunkLoadError'
      expect(isChunkLoadError(named)).toBe(true)
      expect(isChunkLoadError(new Error('boom'))).toBe(false)
      expect(isChunkLoadError(null)).toBe(false)
    })
  })
})
