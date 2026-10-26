// Copied from redact-secrets hooks/register.tsx (NATIONAL_IDS, SECRETS, NOT_A_PHONE, NOT_A_KEY, PATTERNS, luhn, redact): keep in sync.
const NATIONAL_IDS = {
  IT: /\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b/gi, // codice fiscale
  US: /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
  GB: /\b[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g, // National Insurance number
  ES: /\b(?:\d{8}|[XYZ]\d{7})[A-Z]\b/g, // DNI / NIE
  FR: /\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b/g, // NIR
  BR: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, // CPF
  IN: /\b[A-Z]{5}\d{4}[A-Z]\b/g, // PAN
  MX: /\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b/g, // CURP
  CN: /\b\d{17}[\dX]\b/g, // resident identity card
}

// Run before national IDs, so no ID pattern takes a piece of a key.
const SECRETS = [
  ['key', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g],
  ['key', /(?<=\bBearer\s+)[A-Za-z0-9._~+\/-]{16,}=*/g],
  // A digit, +, / or = sets base64 credentials apart from prose like "Basic Authentication".
  ['key', /(?<=\bBasic\s+)(?=[A-Za-z0-9+\/]*[\d+\/=])[A-Za-z0-9+\/]{8,}=*/g],
  ['key', /\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|[rs]k_(?:live|test)_[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[abposre]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[A-Za-z0-9_-]*(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{32,})\b/g],
  // The password in scheme://user:password@host.
  ['secret', /(?<=:\/\/[^\s:@\/]*:)[^\s@\/]+(?=@)/g],
  // The value of PASSWORD=…, "api_key": "…", client_secret: …; not env lookups like process.env.X or ${X}.
  // (?<!⟦): the `secret:` label of a placeholder is not an assignment.
  // (?<![a-z])pass: DB_PASS, not bypass or compass.
  ['secret', /(?<=(?<!⟦)(?:passw(?:or)?d|(?<![a-z])pass\b|pwd|secret(?:[_-]?key)?|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?)(?![$%{(<⟦]|[A-Za-z_]\w*[.([])[^\s"'`,;]{4,}/gi],
]

// Dates, times, IPv4 addresses and build numbers look like phone numbers but are not secret.
// A build has a one-digit group inside (130.0.6723.91); dotted phones do not (06.12.34.56.78, 1.800.555.1234).
const NOT_A_PHONE = /^(?:\d{4}([./-])\d{2}\1\d{2}|\d{1,2}([./-])\d{1,2}\2\d{4})(?: \d{1,2})?$|^\d{1,3}(?:\.\d{1,3}){3}$|^\d+(?:\.\d+)*\.\d(?:\.\d+)+$/

// Git commit hashes, SHA-256 digests and UUIDs fill tool output and are not secret.
const NOT_A_KEY = /^(?:[\da-f]{40}|[\da-f]{64}|[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12})$/i

// Order matters: IBANs before phones, so their digits are not taken as a number.
const PATTERNS = [
  ['email', /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.\p{L}{2,}/gu],
  ['bank_account', /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g],
  ['card', /(?<!\p{Nd})(?:\p{Nd}[ -]?){13,19}(?!\p{Nd})/gu],
  ['phone', /(?:\+|(?<!\p{Nd})00)?\(?\p{Nd}[\p{Nd} ().\/-]{6,}\p{Nd}(?!\p{Nd})/gu],
]

// Every card number passes the Luhn check; most timestamps and order numbers do not.
const luhn = digits =>
  digits.reverse().reduce((sum, d, i) => sum + (i % 2 ? (d * 2 > 9 ? d * 2 - 9 : d * 2) : d), 0) % 10 === 0

const redact = (text, ids = Object.values(NATIONAL_IDS)) =>
  [...SECRETS, ...ids.map(re => ['id', re]), ...PATTERNS].reduce(
    (t, [kind, re]) =>
      t.replace(re, m =>
        ((kind === 'card' || kind === 'phone' || kind === 'bank_account') && (m.match(/\p{Nd}/gu) ?? []).length < 8) ||
        // A long number that fails Luhn is left for the phone pattern, which still masks it.
        (kind === 'card' && !luhn((m.match(/\p{Nd}/gu) ?? []).map(d => +d))) ||
        (kind === 'phone' && NOT_A_PHONE.test(m)) ||
        (kind === 'key' && NOT_A_KEY.test(m))
          ? m
          : `⟦${kind}:${m.slice(0, 3)}•••⟧`,
      ),
    text,
  )

if (typeof module !== 'undefined') module.exports = { redact }
