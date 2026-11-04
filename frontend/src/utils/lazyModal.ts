import { defineComponent, h, nextTick, ref, shallowRef, watch, type Component } from 'vue'
import { i18n } from '@/i18n'
import { useAppStore } from '@/stores/app'

// 与 router.onError 共用同一个 sessionStorage 键和 10 秒窗口，二者合计在 10 秒内最多自动刷新一次，避免循环刷新
const CHUNK_RELOAD_KEY = 'chunk_reload_attempted'
const CHUNK_RELOAD_WINDOW_MS = 10000

export function isChunkLoadError(error: unknown): boolean {
  const e = error as { message?: string; name?: string } | null
  const message = e?.message ?? ''
  return (
    message.includes('Failed to fetch dynamically imported module') ||
    message.includes('error loading dynamically imported module') ||
    message.includes('Importing a module script failed') ||
    message.includes('Loading chunk') ||
    message.includes('Loading CSS chunk') ||
    e?.name === 'ChunkLoadError'
  )
}

/** chunk 加载失败（多为发版后旧 chunk 已删除）时整页刷新一次；10 秒内已刷新过则返回 false。 */
export function tryReloadForChunkError(): boolean {
  try {
    const last = sessionStorage.getItem(CHUNK_RELOAD_KEY)
    const now = Date.now()
    if (last && now - parseInt(last, 10) <= CHUNK_RELOAD_WINDOW_MS) return false
    sessionStorage.setItem(CHUNK_RELOAD_KEY, now.toString())
  } catch {
    return false
  }
  console.warn('[lazyModal] chunk load error detected, reloading page to fetch latest version...')
  window.location.reload()
  return true
}

/**
 * 把体积大的弹窗包装成“首次打开时才加载”的组件（L-11）。
 *
 * - 父组件模板不用改：照常写 `<XxxModal :show="showXxx" @close="..." />`，其余 props、事件、插槽原样透传。
 * - 第一次 show 变为 true 时才下载弹窗 chunk；之前什么也不渲染。
 * - 弹窗总是先以 show=false 挂载，下一个 tick 再把 show 置为 true。这样弹窗内部
 *   `watch(() => props.show, ...)`（非 immediate）的打开逻辑会照常触发，
 *   行为和原来“常驻挂载、靠 show 开关”的方式一致。
 * - 加载失败时（D-1）：
 *   1. 触发父组件的 close 事件，让父组件把 show 复位为 false（与弹窗自身的关闭方式一致），
 *      这样再次点击会重新加载，依赖“是否有弹窗打开”的自动刷新也会恢复；
 *   2. 若是 chunk 加载错误（多为发版后旧 chunk 已被删除），按 router.onError 的做法整页刷新一次，
 *      10 秒内不重复刷新；
 *   3. 否则（或刷新被防抖拦下）用全局 toast 提示用户重试或刷新。
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

      const handleLoadError = (error: unknown) => {
        console.error('[lazyModal] failed to load modal component:', error)
        // 复位父组件的 open 状态
        const onClose = attrs.onClose
        if (typeof onClose === 'function') {
          onClose()
        } else if (Array.isArray(onClose)) {
          onClose.forEach((fn) => typeof fn === 'function' && fn())
        }
        if (isChunkLoadError(error) && tryReloadForChunkError()) return
        try {
          useAppStore().showError(i18n.global.t('common.componentLoadFailed'))
        } catch (toastError) {
          console.error('[lazyModal] failed to show toast:', toastError)
        }
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
            handleLoadError(error)
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
