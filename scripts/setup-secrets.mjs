import { randomBytes } from 'node:crypto'
import { existsSync, writeFileSync, readFileSync } from 'node:fs'
const key = () => randomBytes(32).toString('base64url')
if (existsSync('.secrets.json')) {
  console.log('Existing secrets preserved. Use .connection-keys.txt for the connection keys.')
  process.exit(0)
}
const admin = key(),
  brook = key(),
  renda = key()
const secrets = {
  AIM_TOKEN: admin,
  AIM_IDENTITIES: JSON.stringify({ 'brook-dot': brook, 'renda-dot': renda }),
  EVENT_SECRET_KEY: randomBytes(32).toString('base64'),
}
writeFileSync('.secrets.json', JSON.stringify(secrets, null, 2) + '\n', { mode: 0o600, flag: 'wx' })
writeFileSync(
  '.connection-keys.txt',
  `Agent-IM private connection keys. Keep this file private.\n\nBrowser admin key: ${admin}\nBrook Dot connection key: ${brook}\nRenda Dot connection key: ${renda}\n\nEach person enters only their own Dot key in the OAuth connection screen.\nNever put these keys in a message to an agent or in a URL.\n`,
  { mode: 0o600, flag: 'wx' },
)
if (!existsSync('.dev.vars'))
  writeFileSync(
    '.dev.vars',
    Object.entries(secrets)
      .map(([k, v]) => `${k}='${v}'`)
      .join('\n') + '\n',
    { mode: 0o600, flag: 'wx' },
  )
console.log(
  'Created private .secrets.json, .connection-keys.txt and .dev.vars (permissions 0600). No keys printed.',
)
