// Run with `node redact.test.js`: same cases as the mod's register.test.ts, so drift shows up.
const assert = require('node:assert')
const { redact } = require('./redact.js')

for (const [input, expected] of [
  ['mail mario.rossi@gmail.com ok', 'mail ⟦email:mar•••⟧ ok'],
  ['tel +39 333 123 4567', 'tel ⟦phone:+39•••⟧'],
  ['key sk-ant-api03-abcdefghijklmnopqrstuvwxyz', 'key ⟦key:sk-•••⟧'],
  ['carta 4111 1111 1111 1111', 'carta ⟦card:411•••⟧'],
  ['IT60 X054 2811 1010 0000 0123 456', '⟦iban:IT6•••⟧'],
  ['cf RSSMRA85T10A562S', 'cf ⟦id:RSS•••⟧'],
  ['ho 3 gatti e 2024 anni', 'ho 3 gatti e 2024 anni'],
  ['PASSWORD=hunter2isgood', 'PASSWORD=⟦secret:hun•••⟧'],
  ['{"api_key": "abc123xyz"}', '{"api_key": "⟦secret:abc•••⟧"}'],
  ['GITHUB_TOKEN: x9y8z7w6', 'GITHUB_TOKEN: ⟦secret:x9y•••⟧'],
  ['postgres://admin:S3cretPass@localhost:5432/app', 'postgres://admin:⟦secret:S3c•••⟧@localhost:5432/app'],
  ['stripe sk_live_51HxAbCdEfGhIjKlMn', 'stripe ⟦key:sk_•••⟧'],
  ['Authorization: Bearer abc.def-ghi_jkl0123456', 'Authorization: Bearer ⟦key:abc•••⟧'],
  ['-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\nNzaC1r\n-----END OPENSSH PRIVATE KEY-----', '⟦key:---•••⟧'],
  ['const apiKey = process.env.API_KEY', 'const apiKey = process.env.API_KEY'],
  ['password: ${DB_PASSWORD}', 'password: ${DB_PASSWORD}'],
  ['max_tokens=4096', 'max_tokens=4096'],
  ['at 2026-10-23 12:30:45', 'at 2026-10-23 12:30:45'],
  ['on 23/10/2026', 'on 23/10/2026'],
  ['host 192.168.100.200', 'host 192.168.100.200'],
  ['2026-10-23 333 123 4567', '⟦card:202•••⟧'],
]) assert.strictEqual(redact(input), expected)

console.log('ok')
