import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, RouterLinkStub } from '@vue/test-utils'

import HomeView from '../HomeView.vue'

const { appStore, authStore } = vi.hoisted(() => ({
  appStore: {
    cachedPublicSettings: {} as Record<string, unknown>,
    siteName: 'Fallback site',
    siteLogo: '',
    docUrl: '',
    publicSettingsLoaded: true,
    fetchPublicSettings: vi.fn(),
  },
  authStore: {
    isAuthenticated: false,
    isAdmin: false,
    user: null as { email?: string } | null,
    checkAuth: vi.fn(),
  },
}))

vi.mock('@/stores', () => ({
  useAppStore: () => appStore,
  useAuthStore: () => authStore,
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => appStore,
}))

vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-i18n')>()
  return {
    ...actual,
    useI18n: () => ({ t: (key: string) => key }),
  }
})

function mountHome(settings: Record<string, unknown> = {}) {
  appStore.cachedPublicSettings = {
    site_name: 'Test site',
    site_subtitle: 'Test subtitle',
    ...settings,
  }

  return mount(HomeView, {
    global: {
      stubs: {
        RouterLink: RouterLinkStub,
        LocaleSwitcher: { template: '<div data-testid="locale-switcher" />' },
        Icon: { template: '<span data-testid="icon" />' },
      },
    },
  })
}

function compactDestination(wrapper: ReturnType<typeof mountHome>) {
  return wrapper.get('[data-testid="compact-home"]').findComponent(RouterLinkStub).props('to')
}

function modelPlazaDestination(wrapper: ReturnType<typeof mountHome>) {
  return wrapper
    .findAllComponents(RouterLinkStub)
    .find((link) => link.props('to') === '/model-plaza')
    ?.props('to')
}

describe('HomeView compact mode', () => {
  beforeEach(() => {
    authStore.isAuthenticated = false
    authStore.isAdmin = false
    authStore.user = null
    authStore.checkAuth.mockClear()
    appStore.fetchPublicSettings.mockClear()
    localStorage.clear()
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: false } as MediaQueryList)
  })

  it('renders custom HTML ahead of compact mode', () => {
    const wrapper = mountHome({
      compact_home_enabled: true,
      home_content: '<section id="custom-home">Custom home</section>',
    })

    expect(wrapper.get('#custom-home').text()).toBe('Custom home')
    expect(wrapper.find('[data-testid="compact-home"]').exists()).toBe(false)
  })

  it('renders custom URL content ahead of compact mode', () => {
    const wrapper = mountHome({
      compact_home_enabled: true,
      home_content: ' https://example.com/home ',
    })

    expect(wrapper.get('iframe').attributes('src')).toBe('https://example.com/home')
    expect(wrapper.find('[data-testid="compact-home"]').exists()).toBe(false)
  })

  it('treats whitespace-only custom content as empty and selects compact mode', () => {
    const wrapper = mountHome({ compact_home_enabled: true, home_content: ' \n\t ' })

    expect(wrapper.get('[data-testid="compact-home"]').text()).toContain('Test site')
  })

  it.each([undefined, false])('selects the default home when compact mode is %s', (enabled) => {
    const settings = enabled === undefined ? {} : { compact_home_enabled: enabled }
    const wrapper = mountHome(settings)

    expect(wrapper.find('[data-testid="compact-home"]').exists()).toBe(false)
    expect(wrapper.find('.terminal-container').exists()).toBe(true)
  })

  it('links unauthenticated visitors to login', () => {
    expect(compactDestination(mountHome({ compact_home_enabled: true }))).toBe('/login')
  })

  it('links authenticated users to their dashboard', () => {
    authStore.isAuthenticated = true

    expect(compactDestination(mountHome({ compact_home_enabled: true }))).toBe('/dashboard')
  })

  it('links administrators to the admin dashboard', () => {
    authStore.isAuthenticated = true
    authStore.isAdmin = true

    const wrapper = mountHome({ compact_home_enabled: true })
    expect(compactDestination(wrapper)).toBe('/admin/dashboard')
    expect(authStore.checkAuth).toHaveBeenCalledOnce()
    expect(appStore.fetchPublicSettings).not.toHaveBeenCalled()
  })

  it('shows the model plaza link to anonymous visitors when public access is enabled', () => {
    const wrapper = mountHome({
      compact_home_enabled: true,
      model_plaza_enabled: true,
      model_plaza_require_auth: false,
    })

    expect(modelPlazaDestination(wrapper)).toBe('/model-plaza')
  })

  it('hides the model plaza link from anonymous visitors when sign-in is required', () => {
    const wrapper = mountHome({
      compact_home_enabled: true,
      model_plaza_enabled: true,
      model_plaza_require_auth: true,
    })

    expect(modelPlazaDestination(wrapper)).toBeUndefined()
  })

  it('shows the model plaza link to authenticated visitors when sign-in is required', () => {
    authStore.isAuthenticated = true

    const wrapper = mountHome({
      compact_home_enabled: true,
      model_plaza_enabled: true,
      model_plaza_require_auth: true,
    })

    expect(modelPlazaDestination(wrapper)).toBe('/model-plaza')
  })

  it('shows the model plaza link in the default home header', () => {
    const wrapper = mountHome({
      model_plaza_enabled: true,
      model_plaza_require_auth: false,
    })

    expect(modelPlazaDestination(wrapper)).toBe('/model-plaza')
  })

  it('hides the model plaza link when the feature is disabled', () => {
    const wrapper = mountHome({
      compact_home_enabled: true,
      model_plaza_enabled: false,
      model_plaza_require_auth: false,
    })

    expect(modelPlazaDestination(wrapper)).toBeUndefined()
  })
})

describe('HomeView custom home_content (L-1)', () => {
  it('HTML 模式下渲染前经 DOMPurify 清洗，脚本与事件属性不会进入 DOM', () => {
    const wrapper = mountHome({
      home_content: '<h2 class="t">Welcome</h2><img src=x onerror="window.__xss=1"><script>window.__xss=2</script>',
    })
    const html = wrapper.html()
    expect(html).toContain('<h2 class="t">Welcome</h2>')
    expect(html).not.toMatch(/onerror|<script/i)
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined()
  })

  it('URL 模式仍用 iframe 展示', () => {
    const wrapper = mountHome({ home_content: 'https://example.com/home' })
    expect(wrapper.get('iframe').attributes('src')).toBe('https://example.com/home')
  })

  it('F-1：URL 模式 iframe 带默认 sandbox', () => {
    const wrapper = mountHome({ home_content: 'https://example.com/home' })
    expect(wrapper.get('iframe').attributes('sandbox')).toBe(
      'allow-scripts allow-same-origin allow-popups allow-forms'
    )
  })

  it('F-1：富文本未写 sandbox 的 iframe 也有默认 sandbox', () => {
    const wrapper = mountHome({ home_content: '<iframe src="https://example.com/embed"></iframe>' })
    expect(wrapper.get('iframe').attributes('sandbox')).toBe(
      'allow-scripts allow-same-origin allow-popups allow-forms'
    )
  })

  describe('URL 模式只嵌入 https 绝对地址', () => {
    it.each([
      ['https', 'https://example.com/home', 'https://example.com/home'],
      ['首尾空白/换行', ' \n https://example.com/home?a=1#x \t', 'https://example.com/home?a=1#x'],
      ['大写协议 HTTPS', 'HTTPS://example.com/home', 'HTTPS://example.com/home'],
      ['大小写混合 HtTpS', 'HtTpS://Example.com/', 'HtTpS://Example.com/']
    ])('嵌入：%s', (_name, content, src) => {
      const wrapper = mountHome({ compact_home_enabled: true, home_content: content })
      expect(wrapper.findAll('iframe')).toHaveLength(1)
      expect(wrapper.get('iframe').attributes('src')).toBe(src)
      expect(wrapper.find('[data-testid="home-content-url-blocked"]').exists()).toBe(false)
    })

    it.each([
      ['http', 'http://example.com/home'],
      ['大写 HTTP', 'HTTP://example.com/home'],
      ['大小写混合 hTtP + 空白', '  hTtP://example.com/home  '],
      ['https 但无法解析（IPv6 主机不完整）', 'https://[::1/home'],
      ['https 但无主机', 'https:///'],
    ])('不嵌入：%s，呈现为空白容器，不当作文本/富文本、也不回退到默认首页', (_name, content) => {
      const wrapper = mountHome({ compact_home_enabled: true, home_content: content })
      expect(wrapper.find('iframe').exists()).toBe(false)
      const blocked = wrapper.get('[data-testid="home-content-url-blocked"]')
      expect(blocked.text()).toBe('')
      expect(blocked.element.innerHTML).toBe('')
      expect(wrapper.text()).not.toContain('example')
      expect(wrapper.find('[data-testid="compact-home"]').exists()).toBe(false)
    })

    it('与富文本里 http iframe 被移除时的呈现一致（都是空的自定义首页容器）', () => {
      const urlMode = mountHome({ home_content: 'http://example.com/home' })
      const richMode = mountHome({ home_content: '<iframe src="http://example.com/home"></iframe>' })
      expect(urlMode.find('iframe').exists()).toBe(false)
      expect(richMode.find('iframe').exists()).toBe(false)
      expect(urlMode.text()).toBe('')
      expect(richMode.text()).toBe('')
    })

    it.each([
      ['javascript:', 'javascript:alert(1)//https://example.com'],
      ['JavaScript 大小写', ' JaVaScRiPt:alert(1)'],
      ['data:', 'data:text/html,<script>window.__xss=9</script><img src=x onerror="window.__xss=10">'],
      ['协议相对 //host', '//example.com/home'],
    ])('%s 开头的内容不是 URL 模式，仍走富文本清洗', (_name, content) => {
      const wrapper = mountHome({ home_content: content })
      expect(wrapper.find('iframe').exists()).toBe(false)
      expect(wrapper.find('[data-testid="home-content-url-blocked"]').exists()).toBe(false)
      const html = wrapper.html()
      expect(html).not.toMatch(/<script|onerror/i)
      expect((window as unknown as { __xss?: number }).__xss).toBeUndefined()
    })
  })
})
