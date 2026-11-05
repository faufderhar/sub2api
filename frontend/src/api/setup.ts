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
 * FD2-14: map SETUP_TOKEN_* reasons to frontend i18n copy.
 * Never surface the backend `message` for these codes (locale may differ).
 * Returns null when the error is not a setup-token envelope reason.
 */
export function setupTokenUserMessage(
  err: { reason?: string; retryAfter?: number },
  t: SetupTokenTranslate
): string | null {
  switch (err.reason) {
    case SETUP_TOKEN_REQUIRED:
      return t('setup.setupToken.required')
    case SETUP_TOKEN_INVALID:
      return t('setup.setupToken.invalid')
    case SETUP_TOKEN_RATE_LIMITED:
      return t('setup.setupToken.rateLimited', {
        seconds: err.retryAfter ?? 0
      })
    default:
      return null
  }
}

/** Exposed for unit tests. */
export const __setupClientTestOnly = setupClient
