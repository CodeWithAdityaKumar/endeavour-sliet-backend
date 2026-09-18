import dotenv from 'dotenv'

dotenv.config()

export interface SMTPPayload {
  email: string
  name: string
  regNo?: string
  password?: string
  sendEmailAttachments?: boolean
  whatsappLink?: string
  syllabusFiles?: Array<{ title: string; url: string }>
  coordinators?: Array<{ name: string; role: string; phone: string }>
  attachments?: Array<{ filename: string; url?: string; content?: string }>
}

export async function sendEmailViaMicroservice(payload: SMTPPayload): Promise<boolean> {
  const microserviceUrl = process.env.SMTP_MICROSERVICE_URL || 'http://localhost:4001'
  const secret = process.env.MICROSERVICE_SECRET || 'endeavour_secret_token_2026'

  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 10000)

    const response = await fetch(`${microserviceUrl.replace(/\/$/, '')}/send-registration-emails`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': secret
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    })

    clearTimeout(timeoutId)

    if (response.ok) {
      console.log(`⚡ [SMTP Client] Email payload dispatched to SMTP Microservice (${microserviceUrl})`)
      return true
    } else {
      const err = await response.text()
      console.error(`⚠️ [SMTP Client] Microservice error (${response.status}):`, err)
      return false
    }
  } catch (err: any) {
    if (err.name === 'AbortError') {
      console.warn('⚠️ [SMTP Client] SMTP Microservice connection timed out (10s).')
    } else {
      console.error('⚠️ [SMTP Client] Failed to contact SMTP Microservice:', err.message || err)
    }
    return false
  }
}
