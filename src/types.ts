import { D1Database, DurableObjectNamespace, KVNamespace, Fetcher } from '@cloudflare/workers-types'

export type Bindings = {
  DB: D1Database
  CHAT_ROOM: DurableObjectNamespace
  JWT_SECRET: string
  RESEND_API_KEY: string
  TURNSTILE_SECRET_KEY?: string
  ENCRYPTION_KEY?: string
  COOKIE_DOMAIN?: string
  ASSETS?: Fetcher
  BRIDGE_URL?: string
  BRIDGE_TOKEN?: string
}

export type Variables = {
  user?: {
    uid: string
    username: string
    role: string
    sessionId: string
  }
}

export type Message = {
  msg_id: string
  sender_username: string
  sender_uid: string
  channel: string
  timestamp: number
  text: string
  is_deleted?: boolean
  is_censored?: boolean
  is_bridged?: boolean
}
