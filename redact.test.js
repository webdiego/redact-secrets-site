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
]) assert.strictEqual(redact(input), expected)

console.log('ok')
