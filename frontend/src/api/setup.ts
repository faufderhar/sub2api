/**
 * Setup API endpoints
 */
import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { buildGatewayUrl } from './url'
import { parseRetryAfter } from '@/utils/retryAfter'

// Create a separate client for setup endpoints (not under /api/v1)
const setupClient = axios.create({
  baseURL: buildGatewayUrl('/').replace(/\/+$/, ''),
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

/** In-memory setup token for X-Setup-Token on test-db / test-redis / install. */
let setupToken = ''

export function setSetupToken(token: string): void {
  setupToken = (token || '').trim()
}

export function getSetupToken(): string {
  return setupToken
}

setupClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = setupToken
  if (token) {
    config.headers = config.headers ?? {}
    config.headers['X-Setup-Token'] = token
  }
  return config
})

export interface SetupStatus {
  needs_setup: boolean
  step: string
  /** When true, wizard must collect and send X-Setup-Token (L-8 / F-5). */
  setup_token_required?: boolean
}

export interface DatabaseConfig {
  host: string
  port: number
  user: string
  password: string
  dbname: string
  sslmode: string
}

export interface RedisConfig {
  host: string
  port: number
  username: string
  password: string
  db: number
  enable_tls: boolean
}

export interface AdminConfig {
  email: string
  password: string
}

export interface ServerConfig {
  host: string
  port: number
  mode: string
}

export interface InstallRequest {
  database: DatabaseConfig
  redis: RedisConfig
  admin: AdminConfig
  server: ServerConfig
}

export interface InstallResponse {
  message: string
  restart: boolean
}

export const SETUP_TOKEN_REQUIRED = 'SETUP_TOKEN_REQUIRED'
export const SETUP_TOKEN_INVALID = 'SETUP_TOKEN_INVALID'
export const SETUP_TOKEN_RATE_LIMITED = 'SETUP_TOKEN_RATE_LIMITED'

function envelopeMarker(data: unknown): string {
  if (!data || typeof data !== 'object') return ''
  const d = data as { reason?: unknown; code?: unknown }
  for (const v of [d.reason, d.code]) {
    if (typeof v === 'string' && v.startsWith('SETUP_TOKEN')) return v
  }
  return ''
}

/** Normalize axios errors so the wizard can read message / reason / retryAfter. */
export function normalizeSetupError(error: unknown): {
  message: string
  reason: string
  status?: number
  retryAfter?: number
} {
  const ax = error as AxiosError<{
    detail?: string
    message?: string
    reason?: string
    code?: string | number
  }>
  const data = ax.response?.data
  const status = ax.response?.status
  const reason = envelopeMarker(data)
  const message =
    (typeof data?.message === 'string' && data.message) ||
    (typeof data?.detail === 'string' && data.detail) ||
    ax.message ||
    'Request failed'
  const raw = ax.response?.headers?.['retry-after'] ?? ax.response?.headers?.['Retry-After']
  const retryAfter = parseRetryAfter(raw)
  return { message, reason, status, retryAfter }
}

/**
 * Get setup status
 */
export async function getSetupStatus(): Promise<SetupStatus> {
  const response = await setupClient.get('/setup/status')
  return response.data.data
}

/**
 * Test database connection
 */
export async function testDatabase(config: DatabaseConfig): Promise<void> {
  await setupClient.post('/setup/test-db', config)
}

/**
 * Test Redis connection
 */
export async function testRedis(config: RedisConfig): Promise<void> {
  await setupClient.post('/setup/test-redis', config)
}

/**
 * Perform installation
 */
export async function install(config: InstallRequest): Promise<InstallResponse> {
  const response = await setupClient.post('/setup/install', config)
  return response.data.data
}


export type SetupTokenTranslate = (
  key: string,
  params?: Record<string, unknown>
) => string

/**
 * FD2-14 / FD2-17: map SETUP_TOKEN_* (and bare 429) to frontend i18n copy.
 * Never surface the backend `message` for these cases (locale may differ).
 *
 * FD2-17: RATE_LIMITED / HTTP 429 use the seconds template only when
 * `retryAfter` is a number > 0; otherwise use `rateLimitedNoWait`.
 * A 429 with no `reason` is still treated as rate-limited (restores the
 * pre-bac3c2da1 `status === 429` path that FD2-14 accidentally narrowed).
 */
export function setupTokenUserMessage(
  err: { reason?: string; retryAfter?: number; status?: number },
  t: SetupTokenTranslate
): string | null {
  if (err.reason === SETUP_TOKEN_REQUIRED) {
    return t('setup.setupToken.required')
  }
  if (err.reason === SETUP_TOKEN_INVALID) {
    return t('setup.setupToken.invalid')
  }
  const rateLimited =
    err.reason === SETUP_TOKEN_RATE_LIMITED || err.status === 429
  if (!rateLimited) return null
  const seconds = err.retryAfter
  if (typeof seconds === 'number' && seconds > 0) {
    return t('setup.setupToken.rateLimited', { seconds })
  }
  return t('setup.setupToken.rateLimitedNoWait')
}

/** Exposed for unit tests. */
export const __setupClientTestOnly = setupClient
