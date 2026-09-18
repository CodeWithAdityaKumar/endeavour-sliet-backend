import path from 'path'
import fs from 'fs'
import dotenv from 'dotenv'
import { fileURLToPath } from 'url'
import { db } from './firebase.js'

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export interface AttachmentOption {
  filename: string
  path?: string
  url?: string
  content?: string
}

async function getAccessToken(): Promise<string> {
  const clientId = process.env.GOOGLE_CLIENT_ID
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET
  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN

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
      } else if (att.path && fs.existsSync(att.path)) {
        try {
          const fileBuffer = fs.readFileSync(att.path)
          base64Data = fileBuffer.toString('base64')
        } catch (e: any) {
          console.error(`Error reading local attachment file ${att.path}:`, e.message || e)
        }
      } else if (att.url) {
        try {
          const res = await fetch(att.url)
          if (res.ok) {
            const buffer = await res.arrayBuffer()
            const bytes = new Uint8Array(buffer)
            let binary = ''
            for (let i = 0; i < bytes.byteLength; i++) {
              binary += String.fromCharCode(bytes[i])
            }
            base64Data = btoa(binary)
          }
        } catch (e: any) {
          console.error(`Error fetching attachment URL ${att.url}:`, e.message || e)
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

// Dispatch email using Gmail REST API via HTTPS fetch()
async function dispatchEmail(mailOptions: any, contextLabel: string, retries = 2): Promise<boolean> {
  const gmailUser = process.env.GMAIL_USER || process.env.SMTP_USER || 'ubuntu.surya@gmail.com'
  const defaultFrom = `Endeavour SLIET <${gmailUser}>`

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const accessToken = await getAccessToken()
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
      console.log(`✅ [Gmail REST API] ${contextLabel} sent successfully (ID: ${result.id})`)
      return true
    } catch (error: any) {
      console.error(`❌ [Gmail REST API] ${contextLabel} failed (Attempt ${attempt}/${retries}):`, error.message || error)

      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, 2000))
        continue
      }
      return false
    }
  }
  return false
}

export const sendRegistrationEmail = async (toEmail: string, name: string): Promise<boolean> => {
  // Load custom configurations from settings/general Firestore document
  let sendEmailAttachments = false
  let whatsappLink = 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR'
  let syllabusLink = ''
  let syllabusFiles: Array<{ title: string, url: string }> = []
  let coordinators = [
    { name: 'Ashutosh Mehta', role: 'Coordinator', phone: '+919027042638' },
    { name: 'Anmol Ranjan', role: 'Coordinator & Treasurer', phone: '+916201957167' }
  ]

  if (db) {
    try {
      const settingsDoc = await db.collection('settings').doc('general').get()
      if (settingsDoc.exists) {
        const settingsData = settingsDoc.data()
        if (settingsData?.sendEmailAttachments !== undefined) sendEmailAttachments = settingsData.sendEmailAttachments === true
        if (settingsData?.whatsappLink) whatsappLink = settingsData.whatsappLink
        if (settingsData?.syllabusLink) syllabusLink = settingsData.syllabusLink
        if (Array.isArray(settingsData?.syllabusFiles) && settingsData.syllabusFiles.length > 0) {
          syllabusFiles = settingsData.syllabusFiles
        }
        if (settingsData?.contactDetails && Array.isArray(settingsData.contactDetails) && settingsData.contactDetails.length > 0) {
          coordinators = settingsData.contactDetails
        }
      }
    } catch (e) {
      console.error('Failed to load custom settings inside sendRegistrationEmail:', e)
    }
  }

  const emailAttachments: Array<{ filename: string, path: string, cid?: string }> = []

  // If syllabusFiles is empty from Firestore, try loading from fallbackSettings.json
  if (syllabusFiles.length === 0) {
    try {
      const fallbackPaths = [
        path.resolve(process.cwd(), 'src/config/fallbackSettings.json'),
        path.resolve(process.cwd(), 'dist/config/fallbackSettings.json'),
        path.resolve(process.cwd(), 'fallbackSettings.json'),
        path.resolve(__dirname, 'fallbackSettings.json')
      ]
      for (const p of fallbackPaths) {
        if (fs.existsSync(p)) {
          const fallbackData = JSON.parse(fs.readFileSync(p, 'utf8'))
          if (fallbackData.sendEmailAttachments !== undefined) sendEmailAttachments = fallbackData.sendEmailAttachments === true
          if (Array.isArray(fallbackData.syllabusFiles) && fallbackData.syllabusFiles.length > 0) {
            syllabusFiles = fallbackData.syllabusFiles
            break
          }
        }
      }
    } catch (e) {
      console.warn('Could not read fallbackSettings.json for syllabus links:', e)
    }
  }

  // Optionally attach heavy PDF files if Super Admin enabled sendEmailAttachments toggle
  if (sendEmailAttachments && syllabusFiles.length > 0) {
    for (const f of syllabusFiles) {
      if (!f || !f.url) continue
      const rawTitle = f.title || path.basename(f.url)
      const filename = rawTitle.toLowerCase().endsWith('.pdf') ? rawTitle : `${rawTitle}.pdf`

      if (f.url.startsWith('http://') || f.url.startsWith('https://')) {
        emailAttachments.push({ filename, path: f.url })
      } else {
        const cleanUrl = f.url.replace(/^\//, '')
        const candidatePaths = [
          path.resolve(process.cwd(), cleanUrl),
          path.resolve(process.cwd(), 'assets', path.basename(cleanUrl)),
          path.resolve(__dirname, '../../assets', path.basename(cleanUrl))
        ]
        const localPath = candidatePaths.find(cp => fs.existsSync(cp))
        if (localPath) {
          emailAttachments.push({ filename, path: localPath })
        }
      }
    }
  }

  const siteBaseUrl = process.env.FRONTEND_URL || 'https://www.endeavoursliet.in'

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
              ${syllabusFiles.length > 0 ? `
                <div style="margin-top: 8px;">
                  ${syllabusFiles.map(f => {
                    const rawUrl = f.url || ''
                    const fullUrl = rawUrl.startsWith('http') ? rawUrl : `${siteBaseUrl.replace(/\/$/, '')}/${rawUrl.replace(/^\//, '')}`
                    return `
                      <div style="margin-bottom: 6px;">
                        <a href="${fullUrl}" target="_blank" style="color: #A00000; font-weight: bold; text-decoration: underline; font-size: 0.95em;">
                          📄 ${f.title || 'Download Syllabus Document'}
                        </a>
                      </div>
                    `
                  }).join('')}
                </div>
              ` : syllabusLink ? `
                <div style="margin-top: 8px;">
                  <a href="${syllabusLink}" target="_blank" style="color: #A00000; font-weight: bold; text-decoration: underline; font-size: 0.95em;">
                    📄 Download Syllabus Document
                  </a>
                </div>
              ` : `
                <br><em style="color: #666;">Check the student portal for latest syllabus details.</em>
              `}
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
    attachments: emailAttachments
  }

  return await dispatchEmail(mailOptions, 'Registration email')
}

export const sendAdminCredentialsEmail = async (toEmail: string, name: string, password: string): Promise<boolean> => {
  const mailOptions = {
    to: toEmail,
    subject: 'Welcome to Team Endeavour Admin Portal! 🛡️',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #A00000; text-align: center;">Team Endeavour Admin Portal</h2>
        <p>Hello <strong>${name}</strong>,</p>
        <p>You have been added as an Administrator for the <strong>Team Endeavour Recruitment & Management Portal</strong>.</p>
        
        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #A00000; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #333;">Your Login Credentials:</h3>
          <p><strong>Portal URL:</strong> <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/pages/login" style="color: #A00000;">Login Here</a></p>
          <p><strong>Email:</strong> ${toEmail}</p>
          <p><strong>Temporary Password:</strong> <code style="background: #eee; padding: 3px 6px; border-radius: 4px; font-weight: bold;">${password}</code></p>
          <p style="font-size: 0.85em; color: #666; margin-top: 10px;"><em>Note: Please log in and change your password immediately from your Profile tab in the sidebar.</em></p>
        </div>
        
        <p style="margin-top: 20px; font-size: 0.9em; color: #666; border-top: 1px solid #eee; padding-top: 10px; text-align: center;">
          Strive to Create Difference.<br>
          If you did not expect this invitation, please contact the Super Administrator.
        </p>
      </div>
    `
  }

  return await dispatchEmail(mailOptions, 'Admin credentials email')
}

export const sendCandidateCredentialsEmail = async (toEmail: string, name: string, regNo: string, password: string): Promise<boolean> => {
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
          <p><strong>Portal URL:</strong> <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/pages/login" style="color: #A00000; font-weight: bold;">Candidate Login Portal</a></p>
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

  return await dispatchEmail(mailOptions, 'Candidate credentials email')
}

export const sendCustomEmail = async (
  toEmail: string, 
  subject: string, 
  messageHtml: string
): Promise<boolean> => {
  const mailOptions = {
    to: toEmail,
    subject: subject,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 12px; background-color: #ffffff;">
        <div style="text-align: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #A00000;">
          <img src="https://www.endeavoursliet.in/images/mainlogo.png" alt="Team Endeavour Logo" style="max-height: 80px; width: auto;" />
          <h2 style="color: #A00000; margin: 10px 0 0 0; font-size: 1.4em;">Team Endeavour - SLIET</h2>
        </div>
        
        <div style="color: #333333; line-height: 1.6; font-size: 1rem; margin-bottom: 25px;">
          ${messageHtml}
        </div>
        
        <div style="margin-top: 25px; font-size: 0.85em; color: #777; border-top: 1px solid #eee; padding-top: 15px; text-align: center;">
          <strong style="color: #A00000;">Team Endeavour</strong> - Strive to Create Difference.<br>
          Sant Longowal Institute of Engineering and Technology (SLIET)
        </div>
      </div>
    `
  }

  return await dispatchEmail(mailOptions, `Custom email to ${toEmail}`)
}

export const sendStageNotificationEmail = async (
  toEmail: string, 
  name: string, 
  stage: number, 
  dateTime: string, 
  venue: string, 
  instructions: string
): Promise<boolean> => {
  let stageTitle = ''
  let subject = ''
  let description = ''

  if (stage === 1) {
    stageTitle = 'Stage 1: Aptitude Test Invitation 📝'
    subject = 'Team Endeavour - Aptitude Test Invitation 📝'
    description = `You have been selected for the <strong>Aptitude Test</strong> round. This test evaluates your basic problem-solving abilities and core domains skillsets.`
  } else if (stage === 2) {
    stageTitle = 'Stage 2: Primary Interview Invitation 🗣️'
    subject = 'Team Endeavour - Recruitment Interview Call 🗣️'
    description = `You have been invited for the <strong>Primary Interview</strong> round. In this stage, we evaluate your technical core competence and team fit.`
  } else {
    stageTitle = 'Stage 3: Class & Final Interview Invitation 🚀'
    subject = 'Team Endeavour - Final Evaluation & Class Call 🚀'
    description = `You have been invited for the final stage, which includes a <strong>Learning Session / Class</strong> followed by a <strong>Technical Assessment Interview</strong> related to that session.`
  }

  let whatsappLink = 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR'
  let coordinators = [
    { name: 'Ashutosh Mehta', role: 'Coordinator', phone: '+919027042638' },
    { name: 'Anmol Ranjan', role: 'Coordinator & Treasurer', phone: '+916201957167' }
  ]

  if (db) {
    try {
      const settingsDoc = await db.collection('settings').doc('general').get()
      if (settingsDoc.exists) {
        const settingsData = settingsDoc.data()
        if (settingsData?.whatsappLink) whatsappLink = settingsData.whatsappLink
        if (settingsData?.contactDetails && Array.isArray(settingsData.contactDetails) && settingsData.contactDetails.length > 0) {
          coordinators = settingsData.contactDetails
        }
      }
    } catch (e) {
      console.error('Failed to load custom settings inside sendStageNotificationEmail:', e)
    }
  }

  const mailOptions = {
    to: toEmail,
    subject: subject,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #A00000; text-align: center;">Team Endeavour Recruitment</h2>
        <h3 style="color: #333; text-align: center; border-bottom: 1px solid #eee; padding-bottom: 10px;">${stageTitle}</h3>
        <p>Hello <strong>${name}</strong>,</p>
        <p>${description}</p>
        
        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #A00000; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #333;">Schedule Details:</h3>
          <p><strong>Date & Time:</strong> ${dateTime}</p>
          <p><strong>Venue / Location:</strong> ${venue}</p>
          ${instructions ? `<p><strong>Instructions:</strong> ${instructions}</p>` : ''}
          <p style="margin-top: 15px; margin-bottom: 0;"><strong>WhatsApp Group Link:</strong> <a href="${whatsappLink}" style="color: #25D366; font-weight: bold; text-decoration: none;">Join Here</a></p>
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
          If you have any queries, feel free to reply to this email or contact team coordinators.
        </p>
      </div>
    `
  }

  return await dispatchEmail(mailOptions, `Stage ${stage} notification email to ${toEmail}`)
}

export const sendPasswordResetEmail = async (toEmail: string, name: string, resetLink: string): Promise<boolean> => {
  const mailOptions = {
    to: toEmail,
    subject: 'Password Reset Request - Team Endeavour Portal 🔐',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #A00000; text-align: center;">Team Endeavour Portal</h2>
        <h3 style="color: #333; text-align: center;">Password Reset Request</h3>
        <p>Hello <strong>${name}</strong>,</p>
        <p>We received a request to reset your password for the Team Endeavour Portal.</p>
        
        <div style="background-color: #f9f9f9; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
          <p style="margin-bottom: 15px; font-weight: bold;">Click the button below to reset your password:</p>
          <a href="${resetLink}" style="background-color: #A00000; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password</a>
          <p style="font-size: 0.85em; color: #666; margin-top: 15px;"><em>Or copy and paste this link in your browser:</em><br><a href="${resetLink}" style="color: #A00000; word-break: break-all;">${resetLink}</a></p>
        </div>
        
        <p style="font-size: 0.9em; color: #666;">
          ⚠️ <strong>Note:</strong> This link is valid for 1 hour and can only be used <strong>once</strong>. If you did not request a password reset, please ignore this email.
        </p>

        <p style="margin-top: 20px; font-size: 0.9em; color: #666; border-top: 1px solid #eee; padding-top: 10px; text-align: center;">
          Strive to Create Difference.<br>
          Team Endeavour SLIET
        </p>
      </div>
    `
  }

  return await dispatchEmail(mailOptions, `Password reset email to ${toEmail}`)
}
