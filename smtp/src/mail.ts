import dotenv from 'dotenv'

dotenv.config()

export interface Env {
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  GOOGLE_REFRESH_TOKEN?: string
  GMAIL_USER?: string
  FRONTEND_URL?: string
}

export interface AttachmentOption {
  filename: string
  url?: string
  content?: string
}

async function getAccessToken(env: any): Promise<string> {
  const clientId = env?.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID
  const clientSecret = env?.GOOGLE_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET
  const refreshToken = env?.GOOGLE_REFRESH_TOKEN || process.env.GOOGLE_REFRESH_TOKEN

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('Google OAuth credentials missing (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)')
  }

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Google OAuth token refresh error (${response.status}): ${errorText}`)
  }

  const data = (await response.json()) as { access_token: string }
  return data.access_token
}

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function encodeMIMEHeader(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return `=?UTF-8?B?${btoa(binary)}?=`
}

async function createRawEmail(
  from: string,
  to: string,
  subject: string,
  html: string,
  attachments: AttachmentOption[] = []
): Promise<string> {
  const encodedSubject = encodeMIMEHeader(subject)

  const validAttachments: Array<{ filename: string; base64: string }> = []
  if (attachments && attachments.length > 0) {
    for (const att of attachments) {
      let base64Data = ''
      if (att.content) {
        base64Data = att.content
      } else if (att.url) {
        try {
          console.log(`📎 [Gmail REST API] Fetching attachment: ${att.url}`)
          const res = await fetch(att.url)
          if (res.ok) {
            const buffer = await res.arrayBuffer()
            const bytes = new Uint8Array(buffer)
            let binary = ''
            for (let i = 0; i < bytes.byteLength; i++) {
              binary += String.fromCharCode(bytes[i])
            }
            base64Data = btoa(binary)
            console.log(`✅ [Gmail REST API] Attachment loaded (${att.filename}, ${bytes.byteLength} bytes)`)
          } else {
            console.warn(`⚠️ [Gmail REST API] Could not fetch attachment from ${att.url}: ${res.status}`)
          }
        } catch (e: any) {
          console.error(`⚠️ [Gmail REST API] Attachment fetch error for ${att.url}:`, e.message || e)
        }
      }

      if (base64Data) {
        validAttachments.push({ filename: att.filename, base64: base64Data })
      }
    }
  }

  if (validAttachments.length === 0) {
    const message = [
      `From: ${from}`,
      `To: ${to}`,
      `Subject: ${encodedSubject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=UTF-8',
      '',
      html,
    ].join('\r\n')
    return base64UrlEncode(message)
  }

  const boundary = `----=_Part_${Date.now()}_${Math.random().toString(36).substring(2)}`
  const messageParts = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    html,
  ]

  for (const att of validAttachments) {
    messageParts.push(
      '',
      `--${boundary}`,
      `Content-Type: application/pdf; name="${att.filename}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${att.filename}"`,
      '',
      att.base64
    )
  }

  messageParts.push('', `--${boundary}--`)
  return base64UrlEncode(messageParts.join('\r\n'))
}

export async function dispatchEmail(mailOptions: any, contextLabel: string, customEnv?: any, retries = 2): Promise<boolean> {
  const envObj = customEnv || (globalThis as any).env || process.env
  const gmailUser = envObj.GMAIL_USER || process.env.GMAIL_USER || 'adityakumar9708268593@gmail.com'
  const defaultFrom = `Endeavour SLIET <${gmailUser}>`

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const accessToken = await getAccessToken(envObj)
      const raw = await createRawEmail(
        mailOptions.from || defaultFrom,
        mailOptions.to,
        mailOptions.subject,
        mailOptions.html,
        mailOptions.attachments || []
      )

      const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ raw }),
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Gmail REST API error (${response.status}): ${errorText}`)
      }

      const result = (await response.json()) as { id?: string }
      console.log(`✅ [Gmail REST API] ${contextLabel} sent (Message ID: ${result.id})`)
      return true
    } catch (error: any) {
      console.error(`❌ [Gmail REST API] ${contextLabel} failed (Attempt ${attempt}/${retries}):`, error.message || error)

      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, 2000))
      }
    }
  }

  return false
}

export const sendRegistrationEmail = async (
  toEmail: string,
  name: string,
  customEnv?: any,
  options?: {
    sendEmailAttachments?: boolean
    attachments?: AttachmentOption[]
    whatsappLink?: string
    syllabusFiles?: Array<{ title: string; url: string }>
    coordinators?: Array<{ name: string; role: string; phone: string }>
  }
): Promise<boolean> => {
  const envObj = customEnv || (globalThis as any).env || process.env
  const whatsappLink = options?.whatsappLink || 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR'
  const siteBaseUrl = envObj.FRONTEND_URL || process.env.FRONTEND_URL || 'https://www.endeavoursliet.in'

  const coordinators = (options?.coordinators && options.coordinators.length > 0)
    ? options.coordinators
    : [
        { name: 'Ashutosh Mehta', role: 'Coordinator', phone: '+919027042638' },
        { name: 'Anmol Ranjan', role: 'Coordinator & Treasurer', phone: '+916201957167' }
      ]

  const syllabusFiles = (options?.syllabusFiles && options.syllabusFiles.length > 0)
    ? options.syllabusFiles
    : [{ title: 'Endeavour Assessment 2026', url: `${siteBaseUrl.replace(/\/$/, '')}/assets/Endeavour%20Assessment%202026.pdf` }]

  const attachments: AttachmentOption[] = []
  if (options?.sendEmailAttachments || (options?.attachments && options.attachments.length > 0)) {
    if (options?.attachments && options.attachments.length > 0) {
      attachments.push(...options.attachments)
    } else {
      for (const sf of syllabusFiles) {
        const fileUrl = sf.url.startsWith('http') ? sf.url : `${siteBaseUrl.replace(/\/$/, '')}/${sf.url.replace(/^\//, '')}`
        attachments.push({
          filename: sf.title.endsWith('.pdf') ? sf.title : `${sf.title}.pdf`,
          url: fileUrl
        })
      }
    }
  }

  const mailOptions = {
    to: toEmail,
    subject: 'Registration Successful - Team Endeavour Robotics! 🚀',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #ffffff;">
        <div style="text-align: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #A00000;">
          <img src="https://www.endeavoursliet.in/images/mainlogo.png" alt="Team Endeavour Logo" style="max-height: 80px; width: auto;" />
          <h2 style="color: #A00000; margin: 10px 0 0 0; font-size: 1.4em;">Welcome to Team Endeavour! 🚀</h2>
        </div>

        <p>Hello <strong>${name}</strong>,</p>
        <p>Congratulations! You have successfully registered for <strong>Team Endeavour - SLIET's Robotics Team</strong>.</p>
        
        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #A00000; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #333;">Next Steps:</h3>
          <ol style="padding-left: 20px; margin-bottom: 0;">
            <li><strong>Join our WhatsApp Group</strong> to stay updated on notifications: <br>
              <a href="${whatsappLink}" style="display: inline-block; background-color: #25D366; color: white; padding: 9px 16px; text-decoration: none; border-radius: 6px; font-weight: bold; margin-top: 8px; font-size: 0.95em;">💬 Join WhatsApp Group</a>
            </li>
            <li style="margin-top: 14px;">
              <strong>Syllabus & Study Material Documents:</strong>
              <div style="margin-top: 8px;">
                ${syllabusFiles.map(sf => {
                  const fileUrl = sf.url.startsWith('http') ? sf.url : `${siteBaseUrl.replace(/\/$/, '')}/${sf.url.replace(/^\//, '')}`
                  return `
                    <div style="margin-bottom: 6px;">
                      <a href="${fileUrl}" target="_blank" style="color: #A00000; font-weight: bold; text-decoration: underline; font-size: 0.95em;">
                        📄 ${sf.title}
                      </a>
                    </div>
                  `
                }).join('')}
              </div>
            </li>
          </ol>
        </div>
        
        <h3 style="color: #333; border-bottom: 1px solid #ddd; padding-bottom: 5px;">Endeavour Coordinators:</h3>
        <table style="width: 100%; border-collapse: collapse;">
          ${coordinators.map(c => `
            <tr>
              <td style="padding: 5px 0;"><strong>${c.name}</strong> (${c.role})</td>
              <td style="text-align: right;"><a href="tel:${c.phone}" style="color: #A00000; text-decoration: none;">${c.phone}</a></td>
            </tr>
          `).join('')}
        </table>
        
        <p style="margin-top: 20px; font-size: 0.9em; color: #666; border-top: 1px solid #eee; padding-top: 10px; text-align: center;">
          Strive to Create Difference.<br>
          If you have any questions, feel free to reply to this email or contact us at <a href="mailto:endeavourinsliet@gmail.com" style="color: #A00000;">endeavourinsliet@gmail.com</a>.
        </p>
      </div>
    `,
    attachments
  }

  return await dispatchEmail(mailOptions, 'Registration email', envObj)
}

export const sendCandidateCredentialsEmail = async (
  toEmail: string,
  name: string,
  regNo: string,
  password: string,
  customEnv?: any
): Promise<boolean> => {
  const envObj = customEnv || (globalThis as any).env || process.env
  const siteBaseUrl = envObj.FRONTEND_URL || process.env.FRONTEND_URL || 'https://www.endeavoursliet.in'

  const mailOptions = {
    to: toEmail,
    subject: 'Your Team Endeavour Candidate Portal Login Credentials 🔑',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #A00000; text-align: center;">Team Endeavour Candidate Portal</h2>
        <p>Hello <strong>${name}</strong>,</p>
        <p>Your registration for <strong>Team Endeavour</strong> has been successfully processed! You can now log into your Candidate Portal to view and manage your registration profile.</p>
        
        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #A00000; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #333;">Your Portal Login Credentials:</h3>
          <p><strong>Portal URL:</strong> <a href="${siteBaseUrl}/pages/login" style="color: #A00000; font-weight: bold;">Candidate Login Portal</a></p>
          <p><strong>Email / Reg No:</strong> ${toEmail} / ${regNo}</p>
          <p><strong>Auto-Generated Password:</strong> <code style="background: #eee; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 1.1em; color: #A00000;">${password}</code></p>
          <p style="font-size: 0.85em; color: #666; margin-top: 10px;"><em>Note: You can log in using either your Email or Registration Number with the password above.</em></p>
        </div>
        
        <p style="margin-top: 20px; font-size: 0.9em; color: #666; border-top: 1px solid #eee; padding-top: 10px; text-align: center;">
          Strive to Create Difference.<br>
          Team Endeavour SLIET
        </p>
      </div>
    `
  }

  return await dispatchEmail(mailOptions, 'Candidate credentials email', envObj)
}
