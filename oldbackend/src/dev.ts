import { serve } from '@hono/node-server'
import app from './index.js'

const port = 4000

serve({
  fetch: app.fetch,
  port
}, (info) => {
  console.log(`Server is running on http://localhost:${info.port}`)
})
