import { Hono } from 'hono'
import { sendRegistrationEmail, sendCandidateCredentialsEmail, dispatchEmail } from './mail.js'

export const app = new Hono<{ Bindings: Record<string, string> }>()

// Middleware: Secret token protection for microservice security
app.use('*', async (c, next) => {
  if (c.env) {
    (globalThis as any).env = c.env
    Object.assign(process.env, c.env)
  }

  if (c.req.path === '/health') return await next()

  const envObj = (c.env as Record<string, string> | undefined)
  const secret = process.env.MICROSERVICE_SECRET || envObj?.MICROSERVICE_SECRET || 'endeavour_secret_token_2026'
  const clientSecret = c.req.header('X-API-KEY') || c.req.header('Authorization')?.replace('Bearer ', '')

  if (clientSecret !== secret) {
    return c.json({ error: 'Unauthorized microservice request' }, 401)
  }
  await next()
})

// Health check endpoint
app.get('/health', (c) => c.json({ status: 'ok', service: 'endeavour-smtp-microservice' }))

// Fast Non-Blocking Email Endpoint
app.post('/send-registration-emails', async (c) => {
  try {
    const { email, name, regNo, password, sendEmailAttachments, attachments, whatsappLink, syllabusFiles, coordinators } = await c.req.json()
    if (!email || !name) {
      return c.json({ error: 'Missing required parameters (email, name)' }, 400)
    }

    // Execute background dispatch using Non-Blocking Execution / waitUntil
    const dispatchTask = (async () => {
      console.log(`🚀 [SMTP Microservice] Processing background email task for ${email}`)
      await sendRegistrationEmail(email, name, c.env, { sendEmailAttachments, attachments, whatsappLink, syllabusFiles, coordinators })
      if (regNo && password) {
        await sendCandidateCredentialsEmail(email, name, regNo, password, c.env)
      }
    })()

    // Support Cloudflare Workers ctx.waitUntil safely without throwing in Node.js local mode
    let usedWaitUntil = false
    try {
      if ((c as any).executionCtx && typeof (c as any).executionCtx.waitUntil === 'function') {
        ;(c as any).executionCtx.waitUntil(dispatchTask)
        usedWaitUntil = true
      }
    } catch (e) {
      // Fallback for Node.js dev server
    }

    if (!usedWaitUntil) {
      dispatchTask.catch(err => console.error('Background dispatch error:', err))
    }

    return c.json({
      success: true,
      message: 'Registration email job accepted and dispatched to background queue.'
    })
  } catch (err: any) {
    console.error('SMTP Microservice route error:', err)
    return c.json({ error: err.message || 'Internal server error' }, 500)
  }
})

// Custom email endpoint
app.post('/send-custom-email', async (c) => {
  try {
    const { email, subject, messageHtml } = await c.req.json()
    if (!email || !subject || !messageHtml) {
      return c.json({ error: 'Missing email, subject, or messageHtml' }, 400)
    }

    const dispatchTask = dispatchEmail({ to: email, subject, html: messageHtml }, 'Custom email', c.env)

    let usedWaitUntil = false
    try {
      if ((c as any).executionCtx && typeof (c as any).executionCtx.waitUntil === 'function') {
        ;(c as any).executionCtx.waitUntil(dispatchTask)
        usedWaitUntil = true
      }
    } catch (e) {
      // Fallback for Node.js dev server
    }

    if (!usedWaitUntil) {
      dispatchTask.catch(err => console.error('Custom email error:', err))
    }

    return c.json({ success: true, message: 'Custom email queued.' })
  } catch (err: any) {
    return c.json({ error: err.message }, 500)
  }
})

export default app
