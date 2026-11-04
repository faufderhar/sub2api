import { defineComponent, h, nextTick, ref, shallowRef, watch, type Component } from 'vue'

/**
 * 把体积大的弹窗包装成“首次打开时才加载”的组件（L-11）。
 *
 * - 父组件模板不用改：照常写 `<XxxModal :show="showXxx" ... />`，其余 props、事件、插槽原样透传。
 * - 第一次 show 变为 true 时才下载弹窗 chunk；之前什么也不渲染。
 * - 弹窗总是先以 show=false 挂载，下一个 tick 再把 show 置为 true。这样弹窗内部
 *   `watch(() => props.show, ...)`（非 immediate）的打开逻辑会照常触发，
 *   行为和原来“常驻挂载、靠 show 开关”的方式一致。
 * - 加载失败时（例如发版后旧 chunk 已不存在）在控制台报错，下次打开会重新尝试加载。
 */
export function lazyModal<T extends Component>(loader: () => Promise<{ default: T }>): T {
  const wrapper = defineComponent({
    name: 'LazyModal',
    inheritAttrs: false,
    props: {
      show: { type: Boolean, default: false }
    },
    setup(props, { attrs, slots }) {
      const resolved = shallowRef<Component | null>(null)
      const innerShow = ref(false)
      let loading: Promise<void> | null = null

      const ensureLoaded = (): Promise<void> => {
        if (!loading) {
          loading = loader()
            .then((mod) => {
              resolved.value = mod.default
            })
            .catch((error) => {
              loading = null
              throw error
            })
        }
        return loading
      }

      watch(
        () => props.show,
        async (show) => {
          if (!show) {
            innerShow.value = false
            return
          }
          try {
            await ensureLoaded()
          } catch (error) {
            console.error('[lazyModal] failed to load modal component:', error)
            return
          }
          // 等弹窗以 show=false 完成挂载后再打开
          await nextTick()
          innerShow.value = props.show
        },
        { immediate: true }
      )

      return () =>
        resolved.value ? h(resolved.value, { ...attrs, show: innerShow.value }, slots) : null
    }
  })
  return wrapper as unknown as T
}
