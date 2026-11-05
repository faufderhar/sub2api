/**
 * Parse an HTTP Retry-After header value into remaining seconds.
 * Supports delay-seconds and the three HTTP-date forms from RFC 9110
 * (IMF-fixdate, RFC 850, asctime) — all interpreted as GMT/UTC.
 * Remaining seconds are clamped to [0, 86400]; NaN → 0.
 * Unparseable values return undefined.
 */

export const RETRY_AFTER_MAX_SECONDS = 86_400

const MONTHS: Record<string, number> = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11
}

const WK = '(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)'
const WK_LONG =
  '(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)'
const MON = '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'

/** IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT */
const IMF_FIXDATE = new RegExp(
  `^${WK}, (\\d{2}) (${MON}) (\\d{4}) (\\d{2}):(\\d{2}):(\\d{2}) GMT$`,
  'i'
)

/** RFC 850: Sunday, 06-Nov-94 08:49:37 GMT */
const RFC_850 = new RegExp(
  `^${WK_LONG}, (\\d{2})-(${MON})-(\\d{2}) (\\d{2}):(\\d{2}):(\\d{2}) GMT$`,
  'i'
)

/** asctime: Sun Nov  6 08:49:37 1994 (day may be space-padded) */
const ASCTIME = new RegExp(
  `^${WK} (${MON}) ([ \\d]\\d) (\\d{2}):(\\d{2}):(\\d{2}) (\\d{4})$`,
  'i'
)

function monthIndex(name: string): number | undefined {
  const idx = MONTHS[name.toLowerCase()]
  return idx === undefined ? undefined : idx
}

function y2k(twoDigit: number): number {
  // RFC 850 two-digit year: 00-69 → 2000-2069, 70-99 → 1970-1999 (common POSIX rule)
  return twoDigit >= 70 ? 1900 + twoDigit : 2000 + twoDigit
}

/**
 * Parse an HTTP-date string as GMT/UTC milliseconds since epoch.
 * Does not use Date.parse, so local timezone cannot shift asctime.
 */
export function parseHttpDateUtc(text: string): number | undefined {
  const trimmed = text.trim()

  let m = IMF_FIXDATE.exec(trimmed)
  if (m) {
    const month = monthIndex(m[2])
    if (month === undefined) return undefined
    return Date.UTC(
      Number(m[3]),
      month,
      Number(m[1]),
      Number(m[4]),
      Number(m[5]),
      Number(m[6])
    )
  }

  m = RFC_850.exec(trimmed)
  if (m) {
    const month = monthIndex(m[2])
    if (month === undefined) return undefined
    return Date.UTC(
      y2k(Number(m[3])),
      month,
      Number(m[1]),
      Number(m[4]),
      Number(m[5]),
      Number(m[6])
    )
  }

  m = ASCTIME.exec(trimmed)
  if (m) {
    const month = monthIndex(m[1])
    if (month === undefined) return undefined
    const day = Number(m[2].trim())
    return Date.UTC(
      Number(m[6]),
      month,
      day,
      Number(m[3]),
      Number(m[4]),
      Number(m[5])
    )
  }

  return undefined
}

/** Clamp a computed retry delay into [0, 86400]; NaN → 0. */
export function clampRetryAfterSeconds(seconds: number): number {
  if (!Number.isFinite(seconds) || seconds < 0) return 0
  return Math.min(RETRY_AFTER_MAX_SECONDS, Math.floor(seconds))
}

export function parseRetryAfter(
  value: unknown,
  nowMs: number = Date.now()
): number | undefined {
  if (value == null) return undefined
  const raw = Array.isArray(value) ? value[0] : value
  const text = String(raw).trim()
  if (!text) return undefined

  // Delay-seconds: optional leading +/-, integer only (reject decimals / units).
  if (/^[+-]?\d+$/.test(text)) {
    return clampRetryAfterSeconds(parseInt(text, 10))
  }

  const when = parseHttpDateUtc(text)
  if (when === undefined) return undefined
  return clampRetryAfterSeconds((when - nowMs) / 1000)
}
