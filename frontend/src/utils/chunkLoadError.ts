/**
 * Shared chunk / dynamic-import failure detection and one-shot reload.
 * Used by router.onError, lazyModal, and the vite:preloadError listener.
 */

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
    message.includes('Unable to preload CSS') ||
    e?.name === 'ChunkLoadError'
  )
}

/** chunk 加载失败（多为发版后旧 chunk 已删除）时整页刷新一次；10 秒内已刷新过则返回 false。 */
export function tryReloadForChunkError(source = 'chunkLoadError'): boolean {
  try {
    const last = sessionStorage.getItem(CHUNK_RELOAD_KEY)
    const now = Date.now()
    if (last && now - parseInt(last, 10) <= CHUNK_RELOAD_WINDOW_MS) return false
    sessionStorage.setItem(CHUNK_RELOAD_KEY, now.toString())
  } catch {
    return false
  }
  console.warn(`[${source}] chunk load error detected, reloading page to fetch latest version...`)
  window.location.reload()
  return true
}

/**
 * Register Vite's vite:preloadError handler once. Safe to call multiple times.
 * Vite fires this when a preload (JS/CSS) fails after a deploy rolls assets.
 */
let preloadListenerInstalled = false
export function installVitePreloadErrorHandler(): void {
  if (typeof window === 'undefined' || preloadListenerInstalled) return
  preloadListenerInstalled = true
  window.addEventListener('vite:preloadError', ((event: Event) => {
    // Prevent Vite's default unhandled rejection noise; we own the recovery.
    event.preventDefault?.()
    if (!tryReloadForChunkError('vite:preloadError')) {
      console.error('[vite:preloadError] chunk load error persists after reload. Please clear browser cache.')
    }
  }) as EventListener)
}

export const __chunkLoadErrorTestOnly = {
  CHUNK_RELOAD_KEY,
  CHUNK_RELOAD_WINDOW_MS,
  resetPreloadListenerFlag() {
    preloadListenerInstalled = false
  }
}
