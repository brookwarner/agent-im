import { createHash, timingSafeEqual } from 'node:crypto'
import type { Env } from '../types.js'

export const hash = (value: string) => createHash('sha256').update(value).digest('hex')
export const equal = (a: string, b: string) =>
  timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)))
export function identityForToken(env: Env, token: string): string | null {
  if (env.AIM_TOKEN && equal(token, env.AIM_TOKEN)) return 'admin'
  const identities: Record<string, string> = JSON.parse(env.AIM_IDENTITIES || '{}')
  return Object.entries(identities).find(([, secret]) => equal(token, secret))?.[0] ?? null
}
export function activeIdentity(env: Env, identity: string): boolean {
  return identity === 'admin'
    ? !!env.AIM_TOKEN
    : Object.hasOwn(JSON.parse(env.AIM_IDENTITIES || '{}'), identity)
}
export async function authenticate(env: Env, token: string): Promise<string | null> {
  const identity = identityForToken(env, token)
  if (identity) return identity
  const row = await env.DB.prepare(
    'SELECT principal FROM oauth_tokens WHERE token_hash = ? AND kind = ? AND expires_at > ?',
  )
    .bind(hash(token), 'access', Date.now())
    .first<{ principal: string }>()
  return row && activeIdentity(env, row.principal) ? row.principal : null
}
export async function seal(env: Env, plaintext: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    Buffer.from(env.EVENT_SECRET_KEY, 'base64'),
    'AES-GCM',
    false,
    ['encrypt'],
  )
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext),
  )
  return Buffer.concat([iv, Buffer.from(ciphertext)]).toString('base64')
}
export async function unseal(env: Env, encoded: string): Promise<string> {
  const bytes = Buffer.from(encoded, 'base64')
  const key = await crypto.subtle.importKey(
    'raw',
    Buffer.from(env.EVENT_SECRET_KEY, 'base64'),
    'AES-GCM',
    false,
    ['decrypt'],
  )
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(0, 12) },
    key,
    bytes.subarray(12),
  )
  return new TextDecoder().decode(plaintext)
}
