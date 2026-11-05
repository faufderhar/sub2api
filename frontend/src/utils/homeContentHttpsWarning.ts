/**
 * Detect whether home-page content URL input should show an insecure / unsupported tip.
 * F-2 / FD2-4 / FD2-8 / FD2-12.
 */

/** Absolute https URL (case-insensitive scheme). */
const ABSOLUTE_HTTPS = /^https:\/\//i
/** Absolute http URL (insecure). */
const ABSOLUTE_HTTP = /^http:\/\//i

/**
 * FD2-8: prose / free text must not trigger the tip.
 * Only a single whitespace-free token that looks like a URL-ish value is considered.
 */
const ASCII_URLISH_REST = /^[\x21-\x7e]+$/

/** Build a character-class matching whitespace + C0 controls + DEL (FD2-12). */
function junkCharClass(): string {
  // Avoid \xHH literals in source — eslint no-control-regex flags them.
  const parts: string[] = ['\\s']
  for (let c = 0; c <= 0x1f; c++) {
    parts.push('\\u' + c.toString(16).padStart(4, '0'))
  }
  parts.push('\\u007f')
  return '[' + parts.join('') + ']'
}

const JUNK = junkCharClass()

/** Leading whitespace + C0 controls + DEL before scheme sniffing (FD2-12). */
const LEADING_JUNK = new RegExp('^' + JUNK + '+')

/**
 * Scheme letters may be interleaved with whitespace / C0 / DEL (e.g. java\tscript:).
 * Captures (schemeCharsWithJunk)(restAfterColon).
 */
const OBFUSCATED_SCHEME = new RegExp(
  '^([a-zA-Z](?:' + JUNK + '*[a-zA-Z])*)' + JUNK + '*:([\\s\\S]*)$'
)

function collapseSchemeLetters(raw: string): string {
  return raw.replace(new RegExp(JUNK + '+', 'g'), '').toLowerCase()
}

/**
 * FD2-12: javascript / data / vbscript (and obfuscated forms) are dangerous.
 * Not bound by the FD2-8 single-token rule — payloads may contain spaces.
 *
 * Conflict with prose like「data: 今日数据更新」: only treat as dangerous when the
 * character immediately after the scheme colon is non-whitespace (or rest is empty).
 * If the rest starts with whitespace, this rule does not fire; FD2-8 then also
 * rejects the multi-token string, so no tip is shown.
 */
export function looksLikeDangerousHomeScheme(content: string): boolean {
  const s = content.replace(LEADING_JUNK, '')
  const m = OBFUSCATED_SCHEME.exec(s)
  if (!m) return false
  const scheme = collapseSchemeLetters(m[1])
  if (scheme !== 'javascript' && scheme !== 'data' && scheme !== 'vbscript') {
    return false
  }
  const rest = m[2]
  if (rest.length === 0) return true
  // Only dangerous when the first character after ':' is not whitespace.
  return !/^\s/.test(rest)
}

/**
 * FD2-12: non-http(s) schemes (file / ftp / mailto / …) on a single token →
 * 「不支持的地址」. Still subject to FD2-8 single-token (so「ftp: 说明」does not tip).
 * Dangerous schemes are handled by looksLikeDangerousHomeScheme instead.
 */
export function looksLikeUnsupportedHomeSchemeToken(trimmed: string): boolean {
  if (!trimmed || /\s/.test(trimmed) || trimmed.includes('<')) return false
  if (ABSOLUTE_HTTPS.test(trimmed) || ABSOLUTE_HTTP.test(trimmed)) return false
  if (trimmed.startsWith('//')) return false

  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(trimmed)
  if (!m) return false
  const scheme = m[1].toLowerCase()
  if (
    scheme === 'http' ||
    scheme === 'https' ||
    scheme === 'javascript' ||
    scheme === 'data' ||
    scheme === 'vbscript'
  ) {
    return false
  }
  const rest = m[2]
  if (!rest) return true
  return ASCII_URLISH_REST.test(rest)
}

/**
 * FD2-4 / FD2-8: single token that looks like a malformed / incomplete URL
 * (missing //, protocol-relative, broken https). http(s) only — dangerous and
 * other schemes are covered elsewhere.
 */
export function looksLikeMalformedHomeUrlToken(trimmed: string): boolean {
  if (!trimmed || /\s/.test(trimmed) || trimmed.includes('<')) return false
  if (ABSOLUTE_HTTPS.test(trimmed) || ABSOLUTE_HTTP.test(trimmed)) return false

  if (trimmed.startsWith('//')) {
    return ASCII_URLISH_REST.test(trimmed.slice(2)) || trimmed === '//'
  }

  const m = /^(https?):(.+)$/i.exec(trimmed)
  if (!m) return false
  const rest = m[2]
  if (rest.startsWith('//')) return false
  return ASCII_URLISH_REST.test(rest)
}

/** @deprecated Prefer looksLikeMalformedHomeUrlToken; kept for call-site clarity. */
export function looksLikeMalformedHomeUrl(content: string): boolean {
  return looksLikeMalformedHomeUrlToken(content.trim())
}

export function shouldWarnHomeContentHttp(content: string): boolean {
  const trimmed = content.trim()
  if (!trimmed) return false

  // Absolute https URL — only warn if URL constructor rejects it.
  if (ABSOLUTE_HTTPS.test(trimmed)) {
    try {
      // eslint-disable-next-line no-new
      new URL(trimmed)
      return false
    } catch {
      return true
    }
  }

  // Absolute http URL (insecure).
  if (ABSOLUTE_HTTP.test(trimmed)) {
    return true
  }

  // FD2-12 dangerous schemes (ignore single-token; allow spaced payloads).
  if (looksLikeDangerousHomeScheme(content)) {
    return true
  }

  // FD2-12 unsupported non-http(s) schemes (single token).
  if (looksLikeUnsupportedHomeSchemeToken(trimmed)) {
    return true
  }

  // FD2-4 / FD2-8 malformed http(s) / protocol-relative (single token).
  if (looksLikeMalformedHomeUrlToken(trimmed)) {
    return true
  }

  // Rich text: any iframe that is not clearly https will be stripped by the sanitizer.
  if (!trimmed.includes('<')) return false
  try {
    const doc = new DOMParser().parseFromString(trimmed, 'text/html')
    const iframes = Array.from(doc.querySelectorAll('iframe'))
    if (iframes.length === 0) return false
    return iframes.some((el) => {
      const src = (el.getAttribute('src') || '').trim()
      if (!src) return true
      return !ABSOLUTE_HTTPS.test(src)
    })
  } catch {
    return /<iframe\b/i.test(trimmed)
  }
}
