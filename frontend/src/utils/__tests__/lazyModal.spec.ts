import { describe, it, expect, vi } from 'vitest'
import { defineComponent, h, nextTick, ref, watch } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { lazyModal } from '../lazyModal'

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
})
