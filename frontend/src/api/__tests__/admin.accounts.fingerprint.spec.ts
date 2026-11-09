import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, post } = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { get, post }
}))

import { getFingerprint, regenerateFingerprint } from '@/api/admin/accounts'

const summary = {
  applicable: true,
  regenerable: true,
  generation: 1,
  source: 'created' as const,
  user_agent: 'claude-cli/2.1.78 (external, cli)',
  os: 'linux',
  arch: 'x64',
  runtime: 'node',
  runtime_version: 'v24.3.0',
  client_id_prefix: 'a1b2c3d4',
  tls_profile_id: 3,
  tls_profile_name: 'Node.js 24 / Linux',
  tls_binding: 'auto' as const,
  updated_at: '2026-11-07T14:00:00Z',
  account_uuid_present: true,
  account_uuid_changed: false,
  passthrough_user_id: false,
  conflict: false
}

describe('admin account fingerprint API (R3-FP)', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
  })

  it('GETs the fingerprint summary', async () => {
    get.mockResolvedValue({ data: summary })
    await expect(getFingerprint(12)).resolves.toEqual(summary)
    expect(get).toHaveBeenCalledWith('/admin/accounts/12/fingerprint')
  })

  it('POSTs regenerate with confirm, expected_generation and Idempotency-Key', async () => {
    const next = { ...summary, generation: 2, source: 'regenerated' as const }
    post.mockResolvedValue({ data: next })
    await expect(
      regenerateFingerprint(12, { confirm: true, expected_generation: 1 }, { idempotencyKey: 'idem-1' })
    ).resolves.toEqual(next)
    expect(post).toHaveBeenCalledWith(
      '/admin/accounts/12/fingerprint/regenerate',
      { confirm: true, expected_generation: 1 },
      { headers: { 'Idempotency-Key': 'idem-1' } }
    )
  })
})
