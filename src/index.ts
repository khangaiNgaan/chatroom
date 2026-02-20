import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { Bindings, Variables } from './types'
import { get404Html } from './templates/pages'
import auth from './routes/auth'
import user from './routes/user'
import chat from './routes/chat'

// Export Durable Object Class
export { ChatRoom } from './do/chat-room'

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Global Middleware
app.use('*', cors())

// Mount Routes
app.route('/', auth)
app.route('/', user)
app.route('/', chat)

app.get('/*', async (c) => {
  if (c.env.ASSETS) {
    const response = await c.env.ASSETS.fetch(c.req.raw)
    if (response.status !== 404) {
      return response
    }
  }
  return c.notFound()
})

// 404 Handler
app.notFound((c) => {
  const accept = c.req.header('Accept')
  if (accept && accept.includes('application/json')) {
    return c.json({ message: 'Not Found', ok: false }, 404)
  }
  return c.html(get404Html(), 404)
})

// Error Handler
app.onError((err, c) => {
  console.error(`${err}`)
  return c.json({ message: 'Internal Server Error', ok: false }, 500)
})

export default app
