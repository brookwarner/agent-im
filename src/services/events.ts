import { Webhook } from 'standardwebhooks'
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import type { Env, MessageRow } from '../types.js'
import { activeIdentity, equal, hash, seal, unseal } from '../lib/security.js'
import { ServiceError, getThread, normalizeParticipants } from './im.js'

export class EventError extends Error {
  constructor(
    public code: number,
    message: string,
    public reason?: string,
  ) {
    super(message)
  }
}
const argumentsSchema = z.object({ thread_id: z.number().int().positive().optional() }).strict()
const deliverySchema = z
  .object({ mode: z.literal('webhook'), url: z.string().url(), secret: z.string().optional() })
  .strict()
const subscribeSchema = z.object({
  name: z.literal('message.created'),
  arguments: argumentsSchema,
  delivery: deliverySchema.extend({ secret: z.string() }),
  ttlMs: z
    .number()
    .int()
    .min(60_000)
    .max(7 * 86400_000)
    .nullable()
    .optional(),
  cursor: z.null().optional(),
})
export const eventDefinition = {
  name: 'message.created',
  description:
    'A new message from another participant in a shared Agent-IM thread. Own messages and closed threads do not trigger events. Optional thread_id filter. No replay; use read to catch up.',
  delivery: ['webhook'],
  inputSchema: {
    type: 'object',
    properties: { thread_id: { type: 'integer', minimum: 1 } },
    additionalProperties: false,
  },
  payloadSchema: {
    type: 'object',
    properties: {
      thread_id: { type: 'integer' },
      message_id: { type: 'string' },
      sender: { type: 'string' },
      preview: { type: 'string' },
      url: { type: 'string' },
    },
    required: ['thread_id', 'message_id', 'sender', 'preview', 'url'],
    additionalProperties: false,
  },
}

// This private deployment delivers only to explicitly trusted callback providers.
// Arbitrary MCP callback hosts are intentionally unsupported (SSRF boundary).
export function validateCallback(env: Env, raw: string): URL {
  const url = new URL(raw)
  const hosts = (env.MCP_CALLBACK_HOSTS || 'chatgpt.com,api.openai.com,connectors.api.openai.com')
    .split(',')
    .map((h) => h.trim())
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    (url.port && url.port !== '443') ||
    !hosts.includes(url.hostname)
  ) {
    // Record only the hostname and rejection flags; callback paths can contain tokens.
    console.log(
      JSON.stringify({
        event: 'callback_rejected',
        callback_host: url.hostname,
        https: url.protocol === 'https:',
        has_credentials: Boolean(url.username || url.password),
        has_fragment: Boolean(url.hash),
        standard_port: !url.port || url.port === '443',
        allowed_host: hosts.includes(url.hostname),
      }),
    )
    throw new EventError(
      -32015,
      `Callback URL rejected for hostname ${url.hostname}. Ask the owner to inspect callback_rejected diagnostics.`,
      'invalid_url',
    )
  }
  return url
}
function validateSecret(secret: string) {
  if (!/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret))
    throw new EventError(-32602, 'Invalid signing secret')
  const length = Buffer.from(secret.slice(6), 'base64').length
  if (length < 24 || length > 64)
    throw new EventError(-32602, 'Signing key must contain 24–64 bytes')
}
type Subscription = {
  id: string
  principal: string
  callback_url: string
  secret: string
  previous_secret: string | null
  rotated_at: number | null
  expires_at: number
  arguments: string
  active: number
  verified_at: number
}
export async function signedPost(
  env: Env,
  sub: Pick<Subscription, 'id' | 'callback_url' | 'secret' | 'previous_secret' | 'rotated_at'>,
  eventId: string,
  payload: object,
  fetcher: typeof fetch = fetch,
) {
  const url = validateCallback(env, sub.callback_url)
  const body = JSON.stringify(payload)
  if (Buffer.byteLength(body) > 262144) throw new EventError(-32602, 'Payload too large')
  let stage = 'decrypt_signing_key'
  try {
    const signedAt = new Date()
    const signingKey = await unseal(env, sub.secret)
    stage = 'sign_request'
    let signature = new Webhook(signingKey).sign(eventId, signedAt, body)
    if (sub.previous_secret && sub.rotated_at && Date.now() - sub.rotated_at < 300_000) {
      signature +=
        ' ' + new Webhook(await unseal(env, sub.previous_secret)).sign(eventId, signedAt, body)
    }
    stage = 'send_request'
    const response = await fetcher(url.toString(), {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: {
        'Content-Type': 'application/json',
        'webhook-id': eventId,
        'webhook-timestamp': String(Math.floor(signedAt.getTime() / 1000)),
        'webhook-signature': signature,
        'X-MCP-Subscription-Id': sub.id,
      },
      body,
    })
    // Workers supports manual mode; reject redirects without contacting the target.
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel()
      throw new EventError(-32015, 'Callback redirects are not permitted', 'redirect_not_allowed')
    }
    return response
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'Unknown failure'
    console.error(
      JSON.stringify({
        event: 'webhook_request_failed',
        subscription_id: sub.id,
        callback_host: url.hostname,
        stage,
        error_type: error instanceof Error ? error.name : 'unknown',
        detail: detail
          .replace(/https?:\/\/[^\s]+/g, '[url]')
          .replace(/[A-Za-z0-9+/_=-]{24,}/g, '[redacted]')
          .slice(0, 200),
      }),
    )
    throw error
  }
}
export async function requireThread(env: Env, principal: string, id: number) {
  const thread = await getThread(env.DB, id)
  if (
    !thread ||
    (principal !== 'admin' &&
      !normalizeParticipants(thread.participants).some((p) => p.id === principal))
  ) {
    throw new ServiceError('Thread not found', 404)
  }
  return thread
}
export async function subscribe(
  env: Env,
  principal: string,
  input: unknown,
  fetcher: typeof fetch = fetch,
) {
  if (principal === 'admin')
    throw new EventError(-32602, 'Connect using a Dot identity to subscribe')
  const params = subscribeSchema.parse(input)
  validateCallback(env, params.delivery.url)
  validateSecret(params.delivery.secret)
  if (params.arguments.thread_id) await requireThread(env, principal, params.arguments.thread_id)
  const args = JSON.stringify(params.arguments)
  const id =
    'sub_' + hash(JSON.stringify([principal, params.delivery.url, params.name, args])).slice(0, 32)
  const existing = await env.DB.prepare('SELECT * FROM event_subscriptions WHERE id = ?')
    .bind(id)
    .first<Subscription>()
  const encrypted = await seal(env, params.delivery.secret)
  const rotated = existing && !equal(await unseal(env, existing.secret), params.delivery.secret)
  const previous = rotated ? existing.secret : (existing?.previous_secret ?? null)
  const rotatedAt = rotated ? Date.now() : (existing?.rotated_at ?? null)
  // Finite lifetimes only; ChatGPT renews before this deadline.
  const expires = Date.now() + (params.ttlMs ?? 86400_000)
  const needsVerification =
    !existing || rotated || Date.now() - existing.verified_at > 3600_000 || !existing.active
  if (needsVerification) {
    const challenge = randomUUID()
    try {
      const response = await signedPost(
        env,
        {
          id,
          callback_url: params.delivery.url,
          secret: encrypted,
          previous_secret: previous,
          rotated_at: rotatedAt,
        },
        'verification_' + randomUUID(),
        { type: 'verification', challenge },
        fetcher,
      )
      console.log(
        JSON.stringify({
          event: 'subscription_verification',
          subscription_id: id,
          callback_host: new URL(params.delivery.url).hostname,
          http_status: response.status,
        }),
      )
      // Bound response size before parsing it.
      const reader = response.body?.getReader()
      let text = ''
      let bytes = 0
      if (reader) {
        try {
          while (true) {
            const part = await reader.read()
            if (part.done) break
            bytes += part.value.byteLength
            if (bytes > 4096) throw new Error('Oversized verification response')
            text += new TextDecoder().decode(part.value)
          }
        } finally {
          await reader.cancel()
        }
      }
      if (!response.ok || !equal(JSON.parse(text).challenge || '', challenge))
        throw new Error('Challenge mismatch')
    } catch {
      throw new EventError(-32015, 'Callback verification failed', 'challenge_failed')
    }
  }
  await env.DB.prepare(
    `INSERT INTO event_subscriptions
    (id,principal,event_name,arguments,callback_url,secret,previous_secret,rotated_at,expires_at,verified_at,active)
    VALUES (?,?,?,?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,
    previous_secret=excluded.previous_secret,rotated_at=excluded.rotated_at,expires_at=excluded.expires_at,
    verified_at=excluded.verified_at,active=1`,
  )
    .bind(
      id,
      principal,
      params.name,
      args,
      params.delivery.url,
      encrypted,
      previous,
      rotatedAt,
      expires,
      needsVerification ? Date.now() : existing!.verified_at,
    )
    .run()
  console.log(
    JSON.stringify({
      event: 'subscription_saved',
      subscription_id: id,
      principal,
      expires_at: expires,
    }),
  )
  return { id, refreshBefore: new Date(expires).toISOString(), cursor: null, truncated: false }
}
export async function unsubscribe(env: Env, principal: string, input: unknown) {
  const params = z
    .object({
      name: z.literal('message.created'),
      arguments: argumentsSchema,
      delivery: deliverySchema,
    })
    .parse(input)
  const id =
    'sub_' +
    hash(
      JSON.stringify([
        principal,
        params.delivery.url,
        params.name,
        JSON.stringify(params.arguments),
      ]),
    ).slice(0, 32)
  await env.DB.batch([
    env.DB.prepare('UPDATE event_subscriptions SET active = 0 WHERE id = ? AND principal = ?').bind(
      id,
      principal,
    ),
    env.DB.prepare(
      "UPDATE event_deliveries SET status = 'cancelled' WHERE subscription_id = ? AND status IN ('pending','sending')",
    ).bind(id),
  ])
  return {}
}
type Delivery = { id: string; subscription_id: string; message_id: string; attempts: number }
export async function dispatch(env: Env, baseUrl: string, fetcher: typeof fetch = fetch) {
  const now = Date.now()
  // Atomic leases prevent HTTP and cron workers claiming the same delivery.
  const rows = await env.DB.prepare(
    `UPDATE event_deliveries SET status='sending',lease_until=?
    WHERE id IN (SELECT id FROM event_deliveries WHERE
      ((status='pending' AND next_attempt_at<=?) OR (status='sending' AND lease_until<=?))
      ORDER BY created_at LIMIT 20) RETURNING *`,
  )
    .bind(now + 60_000, now, now)
    .all<Delivery>()
  await Promise.all(
    rows.results.map(async (d) => {
      const sub = await env.DB.prepare('SELECT * FROM event_subscriptions WHERE id = ?')
        .bind(d.subscription_id)
        .first<Subscription>()
      const msg = await env.DB.prepare('SELECT * FROM messages WHERE id = ?')
        .bind(d.message_id)
        .first<MessageRow>()
      if (
        !sub ||
        !msg ||
        !sub.active ||
        sub.expires_at <= Date.now() ||
        !activeIdentity(env, sub.principal)
      ) {
        await env.DB.prepare("UPDATE event_deliveries SET status='cancelled' WHERE id=?")
          .bind(d.id)
          .run()
        return
      }
      const thread = await getThread(env.DB, msg.thread_id)
      if (
        !thread ||
        thread.status !== 'open' ||
        !normalizeParticipants(thread.participants).some((p) => p.id === sub.principal) ||
        msg.sender === sub.principal
      ) {
        await env.DB.prepare("UPDATE event_deliveries SET status='cancelled' WHERE id=?")
          .bind(d.id)
          .run()
        return
      }
      let status = 0
      try {
        const response = await signedPost(
          env,
          sub,
          d.id,
          {
            eventId: d.id,
            name: 'message.created',
            timestamp: new Date(
              msg.created_at.endsWith('Z')
                ? msg.created_at
                : msg.created_at.replace(' ', 'T') + 'Z',
            ).toISOString(),
            data: {
              thread_id: msg.thread_id,
              message_id: msg.id,
              sender: msg.sender,
              preview: msg.content.slice(0, 1000),
              url: baseUrl + '/chat#thread-' + msg.thread_id,
            },
            cursor: null,
          },
          fetcher,
        )
        status = response.status
        await response.body?.cancel()
      } catch {
        /* The durable outbox retains failed deliveries. */
      }
      const attempts = d.attempts + 1
      const accepted = status >= 200 && status < 300
      const transient = !status || status === 408 || status === 429 || status >= 500
      const nextStatus = accepted ? 'delivered' : transient && attempts < 8 ? 'pending' : 'failed'
      await env.DB.prepare(
        'UPDATE event_deliveries SET status=?,attempts=?,last_status=?,next_attempt_at=?,lease_until=0 WHERE id=?',
      )
        .bind(
          nextStatus,
          attempts,
          status,
          Date.now() + Math.min(3600_000, 1000 * 2 ** attempts),
          d.id,
        )
        .run()
      if (status === 410)
        await env.DB.prepare('UPDATE event_subscriptions SET active=0 WHERE id=?')
          .bind(sub.id)
          .run()
      console.log(
        JSON.stringify({
          event: 'webhook_delivery',
          delivery_id: d.id,
          status,
          attempts,
          result: nextStatus,
        }),
      )
    }),
  )
}
