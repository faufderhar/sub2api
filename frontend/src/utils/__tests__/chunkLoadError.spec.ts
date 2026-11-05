import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  isChunkLoadError,
  tryReloadForChunkError,
  installVitePreloadErrorHandler,
  __chunkLoadErrorTestOnly
} from '../chunkLoadError'

describe('isChunkLoadError', () => {
  it('matches Chrome dynamic import failures', () => {
    expect(
      isChunkLoadError(
        new TypeError('Failed to fetch dynamically imported module: http://x/a.js')
      )
    ).toBe(true)
  })

  it('matches Firefox dynamic import failures', () => {
    expect(
      isChunkLoadError(
        new TypeError('error loading dynamically imported module: http://x/a.js')
      )
    ).toBe(true)
  })

  it('matches Safari module script failures', () => {
    expect(isChunkLoadError(new TypeError('Importing a module script failed.'))).toBe(true)
  })

  it('matches webpack-style Loading chunk / CSS chunk messages', () => {
    expect(isChunkLoadError(new Error('Loading chunk 3 failed.'))).toBe(true)
    expect(isChunkLoadError(new Error('Loading CSS chunk 5 failed.'))).toBe(true)
  })

  it('matches Unable to preload CSS (Vite)', () => {
    expect(isChunkLoadError(new Error('Unable to preload CSS for /assets/x.css'))).toBe(true)
  })

  it('matches ChunkLoadError by name', () => {
    const err = new Error('boom')
    err.name = 'ChunkLoadError'
    expect(isChunkLoadError(err)).toBe(true)
  })

  it('rejects unrelated errors', () => {
    expect(isChunkLoadError(new Error('boom'))).toBe(false)
    expect(isChunkLoadError(null)).toBe(false)
    expect(isChunkLoadError(undefined)).toBe(false)
  })
})

describe('tryReloadForChunkError', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.stubGlobal('location', { ...window.location, reload: vi.fn() })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    sessionStorage.clear()
  })

  it('reloads once within the debounce window', () => {
    expect(tryReloadForChunkError()).toBe(true)
    expect(window.location.reload).toHaveBeenCalledTimes(1)
    expect(tryReloadForChunkError()).toBe(false)
    expect(window.location.reload).toHaveBeenCalledTimes(1)
  })
})

describe('installVitePreloadErrorHandler', () => {
  beforeEach(() => {
    sessionStorage.clear()
    __chunkLoadErrorTestOnly.resetPreloadListenerFlag()
    vi.stubGlobal('location', { ...window.location, reload: vi.fn() })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    sessionStorage.clear()
    __chunkLoadErrorTestOnly.resetPreloadListenerFlag()
  })

  it('reloads on vite:preloadError', () => {
    installVitePreloadErrorHandler()
    installVitePreloadErrorHandler() // idempotent
    const event = new Event('vite:preloadError')
    const preventDefault = vi.spyOn(event, 'preventDefault')
    window.dispatchEvent(event)
    expect(preventDefault).toHaveBeenCalled()
    expect(window.location.reload).toHaveBeenCalledTimes(1)
  })
})
