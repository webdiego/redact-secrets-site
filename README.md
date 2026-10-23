# redact-secrets-site

Landing page for [redact-secrets](https://github.com/webdiego/redact-secrets), the Claude Code mod that masks sensitive data in prompts before they are sent.

Static HTML, no build step. Open `index.html` or serve the folder.

`redact.js` is a copy of the mod's patterns, used by the in-page playground. Keep it in sync with `hooks/register.tsx`; `node redact.test.js` checks the shared cases.
