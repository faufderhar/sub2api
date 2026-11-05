/**
 * Parse an HTTP Retry-After header value into remaining seconds.
 * Supports both delay-seconds (integer) and HTTP-date forms (RFC 9110).
 * Negative remaining time clamps to 0. Unparseable values return undefined.
 */
export function parseRetryAfter(
  value: unknown,
  nowMs: number = Date.now()
): number | undefined {
  if (value == null) return undefined
  const raw = Array.isArray(value) ? value[0] : value
  const text = String(raw).trim()
  if (!text) return undefined

  // Pure integer seconds (optional leading +); reject decimals / units.
  if (/^\+?\d+$/.test(text)) {
    const seconds = parseInt(text, 10)
    if (Number.isNaN(seconds)) return undefined
    return Math.max(0, seconds)
  }

  // HTTP-date must look like an IMF-fix date (letters + comma or weekday-ish).
  // Reject bare decimals / "30s" that Date.parse may coerce surprisingly.
  if (!/[A-Za-z]/.test(text)) return undefined

  const when = Date.parse(text)
  if (Number.isNaN(when)) return undefined
  return Math.max(0, Math.floor((when - nowMs) / 1000))
}
