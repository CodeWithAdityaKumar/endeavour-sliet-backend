import { serve } from '@hono/node-server'
import dotenv from 'dotenv'
import app from './index.js'

dotenv.config()

const port = Number(process.env.PORT || 4001)

console.log(`⚡ [SMTP Microservice] Starting server on http://localhost:${port}`)
serve({
  fetch: app.fetch,
  port
})
