import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { sign, verify } from 'hono/jwt'
import crypto from 'crypto'

type Bindings = {
  FIREBASE_PROJECT_ID?: string
  FIREBASE_CLIENT_EMAIL?: string
  FIREBASE_PRIVATE_KEY?: string
  CLOUDINARY_CLOUD_NAME?: string
  CLOUDINARY_API_KEY?: string
  CLOUDINARY_API_SECRET?: string
  GOOGLE_SCRIPT_URL?: string
  RECOVERY_GOOGLE_SCRIPT_URL?: string
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  GOOGLE_REFRESH_TOKEN?: string
  GMAIL_USER?: string
  EMAIL_FROM?: string
  ADMIN_EMAIL?: string
  ADMIN_PASSWORD?: string
  JWT_SECRET?: string
  FRONTEND_URL?: string
}

// Security & Password Hashing Helpers
function hashPassword(password: string): string {
  if (!password) return ''
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex')
  return `${salt}:${hash}`
}

function verifyPassword(password: string, storedHash: string): boolean {
  if (!password || !storedHash) return false
  if (!storedHash.includes(':')) {
    return password === storedHash
  }
  try {
    const [salt, originalHash] = storedHash.split(':')
    if (!salt || !originalHash) return false
    const hashToTest = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex')
    return crypto.timingSafeEqual(Buffer.from(hashToTest), Buffer.from(originalHash))
  } catch (e) {
    return false
  }
}

// Convert JS object to Firestore REST Document fields
function objectToFirestoreFields(obj: Record<string, any>): Record<string, any> {
  const fields: Record<string, any> = {}
  for (const [key, val] of Object.entries(obj)) {
    if (val === null || val === undefined) continue
    if (typeof val === 'string') {
      fields[key] = { stringValue: val }
    } else if (typeof val === 'number') {
      fields[key] = Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val }
    } else if (typeof val === 'boolean') {
      fields[key] = { booleanValue: val }
    } else if (typeof val === 'object') {
      fields[key] = { stringValue: JSON.stringify(val) }
    }
  }
  return fields
}

// Convert Firestore REST Document fields to JS object
function firestoreFieldsToObject(fields: Record<string, any> = {}): Record<string, any> {
  const res: Record<string, any> = {}
  for (const [key, valObj] of Object.entries(fields)) {
    if ('stringValue' in valObj) {
      const str = valObj.stringValue
      if (str.startsWith('{') || str.startsWith('[')) {
        try { res[key] = JSON.parse(str) } catch { res[key] = str }
      } else {
        res[key] = str
      }
    } else if ('integerValue' in valObj) res[key] = Number(valObj.integerValue)
    else if ('doubleValue' in valObj) res[key] = Number(valObj.doubleValue)
    else if ('booleanValue' in valObj) res[key] = Boolean(valObj.booleanValue)
    else res[key] = valObj
  }
  return res
}

// Web Crypto RS256 JWT Generator for Google OAuth in Cloudflare Workers
async function signJwtRs256(clientEmail: string, privateKeyPem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'RS256', typ: 'JWT' }
  const claimSet = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  }

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
  const encodedClaimSet = Buffer.from(JSON.stringify(claimSet)).toString('base64url')
  const signatureInput = `${encodedHeader}.${encodedClaimSet}`

  const pemHeader = '-----BEGIN PRIVATE KEY-----'
  const pemFooter = '-----END PRIVATE KEY-----'
  const pemContents = privateKeyPem
    .replace(pemHeader, '')
    .replace(pemFooter, '')
    .replace(/\\n/g, '')
    .replace(/\s/g, '')

  const binaryDer = Buffer.from(pemContents, 'base64')

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const signatureBuffer = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    Buffer.from(signatureInput)
  )

  const signature = Buffer.from(signatureBuffer).toString('base64url')
  return `${signatureInput}.${signature}`
}

let cachedFirestoreToken: { token: string; expiresAt: number } | null = null

async function getFirestoreAccessToken(env: Bindings): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  if (cachedFirestoreToken && cachedFirestoreToken.expiresAt > now + 60) {
    return cachedFirestoreToken.token
  }

  const clientEmail = env.FIREBASE_CLIENT_EMAIL || process.env.FIREBASE_CLIENT_EMAIL || ''
  const privateKey = env.FIREBASE_PRIVATE_KEY || process.env.FIREBASE_PRIVATE_KEY || ''

  if (!clientEmail || !privateKey) {
    throw new Error('Firebase service account credentials missing in environment')
  }

  const jwt = await signJwtRs256(clientEmail, privateKey)

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    })
  })

  if (!res.ok) {
    const errText = await res.text()
    throw new Error(`Failed to obtain Firestore OAuth token: ${errText}`)
  }

  const data: any = await res.json()
  cachedFirestoreToken = {
    token: data.access_token,
    expiresAt: now + data.expires_in
  }
  return data.access_token
}

// Firestore REST API Helpers
async function queryFirestore(collection: string, field: string, value: string, env: Bindings): Promise<any[]> {
  const projectId = env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID missing')

  const token = await getFirestoreAccessToken(env)
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`

  const queryBody = {
    structuredQuery: {
      from: [{ collectionId: collection }],
      where: {
        fieldFilter: {
          field: { fieldPath: field },
          op: 'EQUAL',
          value: { stringValue: value }
        }
      }
    }
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(queryBody)
  })

  if (!res.ok) {
    throw new Error(`Firestore query failed: ${await res.text()}`)
  }

  const results: any = await res.json()
  const documents: any[] = []

  if (Array.isArray(results)) {
    for (const item of results) {
      if (item.document) {
        documents.push({
          id: item.document.name.split('/').pop(),
          ...firestoreFieldsToObject(item.document.fields)
        })
      }
    }
  }

  return documents
}

async function addFirestoreDoc(collection: string, data: Record<string, any>, env: Bindings): Promise<string> {
  const projectId = env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID missing')

  const token = await getFirestoreAccessToken(env)
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}`

  const fields = objectToFirestoreFields(data)

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ fields })
  })

  if (!res.ok) {
    throw new Error(`Firestore doc creation failed: ${await res.text()}`)
  }

  const createdDoc: any = await res.json()
  return createdDoc.name.split('/').pop()
}

async function getFirestoreDoc(collection: string, docId: string, env: Bindings): Promise<any | null> {
  const projectId = env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID missing')

  const token = await getFirestoreAccessToken(env)
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`

  const res = await fetch(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` }
  })

  if (!res.ok) return null
  const docData: any = await res.json()
  return {
    id: docData.name.split('/').pop(),
    ...firestoreFieldsToObject(docData.fields)
  }
}

async function updateFirestoreDoc(collection: string, docId: string, data: Record<string, any>, env: Bindings): Promise<boolean> {
  const projectId = env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID missing')

  const token = await getFirestoreAccessToken(env)
  const fields = objectToFirestoreFields(data)

  const updateMask = Object.keys(data).map(k => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&')
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}?${updateMask}`

  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ fields })
  })

  return res.ok
}

async function deleteFirestoreDoc(collection: string, docId: string, env: Bindings): Promise<boolean> {
  const projectId = env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID missing')

  const token = await getFirestoreAccessToken(env)
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`

  const res = await fetch(url, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` }
  })

  return res.ok
}

async function listFirestoreDocs(collection: string, env: Bindings): Promise<any[]> {
  const projectId = env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT_ID
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID missing')

  const token = await getFirestoreAccessToken(env)
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?pageSize=1000`

  const res = await fetch(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` }
  })

  if (!res.ok) return []
  const data: any = await res.json()
  const documents: any[] = []

  if (Array.isArray(data.documents)) {
    for (const doc of data.documents) {
      documents.push({
        id: doc.name.split('/').pop(),
        ...firestoreFieldsToObject(doc.fields)
      })
    }
  }

  return documents
}

// Gmail REST API Email Dispatch Helper
async function sendEmailViaGmailRest(to: string, subject: string, htmlContent: string, env: Bindings) {
  const clientId = env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID
  const clientSecret = env.GOOGLE_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET
  const refreshToken = env.GOOGLE_REFRESH_TOKEN || process.env.GOOGLE_REFRESH_TOKEN

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('Google OAuth credentials missing in environment')
  }

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  })

  if (!tokenRes.ok) {
    throw new Error(`OAuth refresh failed: ${await tokenRes.text()}`)
  }

  const tokenData: any = await tokenRes.json()
  const accessToken = tokenData.access_token
  const fromEmail = env.EMAIL_FROM || process.env.EMAIL_FROM || 'Endeavour SLIET <ubuntu.surya@gmail.com>'

  const rawMessage = [
    `From: ${fromEmail}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    '',
    htmlContent
  ].join('\r\n')

  const encodedMessage = Buffer.from(rawMessage)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ raw: encodedMessage })
  })

  if (!res.ok) {
    throw new Error(`Gmail API send failed: ${await res.text()}`)
  }

  return await res.json()
}

// Middlewares
async function candidateAuthMiddleware(c: any, next: any) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized: Missing token' }, 401)
  }
  const token = authHeader.split(' ')[1]
  const jwtSecret = c.env.JWT_SECRET || process.env.JWT_SECRET || 'endeavour_secret_key_2025'
  try {
    const payload: any = await verify(token, jwtSecret, 'HS256')
    if (payload.role !== 'candidate') {
      return c.json({ error: 'Unauthorized: Candidate access required' }, 403)
    }
    c.set('jwtPayload', payload)
    await next()
  } catch (err) {
    return c.json({ error: 'Unauthorized: Invalid or expired token' }, 401)
  }
}

async function adminAuthMiddleware(c: any, next: any) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized: Missing token' }, 401)
  }
  const token = authHeader.split(' ')[1]
  const jwtSecret = c.env.JWT_SECRET || process.env.JWT_SECRET || 'endeavour_secret_key_2025'
  try {
    const payload: any = await verify(token, jwtSecret, 'HS256')
    if (payload.role !== 'admin') {
      return c.json({ error: 'Unauthorized: Admin access required' }, 403)
    }
    c.set('jwtPayload', payload)
    await next()
  } catch (err) {
    return c.json({ error: 'Unauthorized: Invalid or expired token' }, 401)
  }
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('*', cors({
  origin: (origin) => origin || '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'Access-Control-Allow-Private-Network'],
  exposeHeaders: ['Content-Length'],
  maxAge: 600,
  credentials: true,
}))

app.use('*', async (c, next) => {
  c.header('Access-Control-Allow-Private-Network', 'true')
  await next()
})

app.get('/', (c) => {
  return c.json({
    message: 'Hello Endeavour Cloudflare Worker Backend!',
    status: 'operational',
    timestamp: new Date().toISOString()
  })
})

// Settings Endpoint
app.get('/api/settings', async (c) => {
  try {
    const docs = await listFirestoreDocs('settings', c.env)
    const settingsObj: Record<string, any> = {
      whatsappLink: 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR',
      recruitmentOpen: true,
      contactDetails: [],
      syllabusLink: '',
      syllabusFiles: []
    }
    if (docs.length > 0) {
      Object.assign(settingsObj, docs[0])
    }
    return c.json({ success: true, settings: settingsObj })
  } catch (err: any) {
    return c.json({
      success: true,
      settings: {
        whatsappLink: 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR',
        recruitmentOpen: true
      }
    })
  }
})

app.post('/api/admin/settings', adminAuthMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const docs = await listFirestoreDocs('settings', c.env)
    let ok = false
    if (docs.length > 0) {
      ok = await updateFirestoreDoc('settings', docs[0].id, body, c.env)
    } else {
      await addFirestoreDoc('settings', body, c.env)
      ok = true
    }
    return c.json({ success: ok, message: 'Settings updated successfully' })
  } catch (err: any) {
    return c.json({ error: `Settings update failed: ${err.message}` }, 500)
  }
})

// Cloudinary Upload Endpoint
app.post('/api/upload', async (c) => {
  try {
    const cloudName = c.env.CLOUDINARY_CLOUD_NAME || process.env.CLOUDINARY_CLOUD_NAME
    const apiKey = c.env.CLOUDINARY_API_KEY || process.env.CLOUDINARY_API_KEY
    const apiSecret = c.env.CLOUDINARY_API_SECRET || process.env.CLOUDINARY_API_SECRET

    if (!cloudName || !apiKey || !apiSecret) {
      return c.json({ error: 'Cloudinary environment variables missing' }, 500)
    }

    const body = await c.req.parseBody()
    const file = body.file as File
    const type = (body.type as string) || 'photo'

    if (!file) {
      return c.json({ error: 'No file provided' }, 400)
    }

    const timestamp = Math.floor(Date.now() / 1000)
    const folder = type === 'photo' ? 'endeavour/photos' : 'endeavour/resumes'
    const strToSign = `folder=${folder}&timestamp=${timestamp}${apiSecret}`
    const signature = crypto.createHash('sha1').update(strToSign).digest('hex')

    const formData = new FormData()
    formData.append('file', file)
    formData.append('api_key', apiKey)
    formData.append('timestamp', String(timestamp))
    formData.append('signature', signature)
    formData.append('folder', folder)

    const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/upload`, {
      method: 'POST',
      body: formData
    })

    if (!res.ok) {
      const errText = await res.text()
      return c.json({ error: `Cloudinary upload failed: ${errText}` }, 500)
    }

    const data: any = await res.json()
    return c.json({ url: data.secure_url, public_id: data.public_id })
  } catch (err: any) {
    return c.json({ error: `Upload error: ${err.message}` }, 500)
  }
})

// Candidates Registration Endpoint
app.post('/api/register', async (c) => {
  try {
    const body = await c.req.json()
    const cleanEmail = String(body.Email || '').trim().toLowerCase()
    const cleanRegNo = String(body.RegNo || '').trim()

    if (!cleanEmail || !cleanRegNo) {
      return c.json({ error: 'Email and Registration Number are required.' }, 400)
    }

    // Check duplicates
    const emailDocs = await queryFirestore('registrations', 'Email', cleanEmail, c.env)
    const regDocs = await queryFirestore('registrations', 'RegNo', cleanRegNo, c.env)

    if (emailDocs.length > 0 || regDocs.length > 0) {
      return c.json({ error: 'Already registered with this Email or Registration Number.' }, 400)
    }

    const rawPassword = body.Password || crypto.randomBytes(4).toString('hex').toLowerCase()
    const record = {
      ...body,
      Email: cleanEmail,
      RegNo: cleanRegNo,
      Password: hashPassword(rawPassword),
      submittedAt: new Date().toISOString(),
      status: 'pending'
    }

    const docId = await addFirestoreDoc('registrations', record, c.env)

    if (c.executionCtx) {
      c.executionCtx.waitUntil(
        sendEmailViaGmailRest(
          cleanEmail,
          'Welcome to Endeavour 2026 - Registration Confirmed',
          `<h1>Welcome ${body.Name || 'Candidate'}!</h1><p>Your registration is confirmed. Your candidate portal login password is: <strong>${rawPassword}</strong></p>`,
          c.env
        ).catch((e) => console.error('Email dispatch error in Worker:', e))
      )
    }

    return c.json({ success: true, id: docId, message: 'Registration successful!' })
  } catch (err: any) {
    return c.json({ error: `Registration failed: ${err.message}` }, 500)
  }
})

// Candidate Auth Login Endpoint (Supports both /api/auth/candidate-login and /api/candidate/login)
const handleCandidateLogin = async (c: any) => {
  try {
    const { identifier, password } = await c.req.json()
    if (!identifier || !password) {
      return c.json({ error: 'Email/RegNo and Password are required' }, 400)
    }

    const cleanInput = String(identifier).trim()
    const cleanInputLower = cleanInput.toLowerCase()

    let candidateDoc: any = null
    const emailDocs = await queryFirestore('registrations', 'Email', cleanInputLower, c.env)
    if (emailDocs.length > 0) {
      candidateDoc = emailDocs[0]
    } else {
      const regDocs = await queryFirestore('registrations', 'RegNo', cleanInput, c.env)
      if (regDocs.length > 0) {
        candidateDoc = regDocs[0]
      }
    }

    if (!candidateDoc) {
      return c.json({ error: 'No account found with this Email or Registration Number.' }, 404)
    }

    const isMatch = verifyPassword(String(password).trim(), candidateDoc.Password || '')
    if (!isMatch) {
      return c.json({ error: 'Invalid password. Please check your password and try again.' }, 401)
    }

    const jwtSecret = c.env.JWT_SECRET || process.env.JWT_SECRET || 'endeavour_secret_key_2025'
    const tokenPayload = {
      id: candidateDoc.id,
      email: candidateDoc.Email,
      regNo: candidateDoc.RegNo,
      role: 'candidate',
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60)
    }

    const token = await sign(tokenPayload, jwtSecret, 'HS256')
    const { Password, ...safeCandidateData } = candidateDoc

    return c.json({
      success: true,
      token,
      candidate: {
        id: candidateDoc.id,
        ...safeCandidateData
      }
    })
  } catch (err: any) {
    return c.json({ error: `Login failed: ${err.message}` }, 500)
  }
}

app.post('/api/auth/candidate-login', handleCandidateLogin)
app.post('/api/candidate/login', handleCandidateLogin)

// Candidate Profile Endpoint (Supports both /api/candidate/me and /api/candidate/profile)
const handleCandidateProfileGet = async (c: any) => {
  try {
    const jwtPayload = c.get('jwtPayload')
    const candidateDoc = await getFirestoreDoc('registrations', jwtPayload.id, c.env)

    if (!candidateDoc) {
      return c.json({ error: 'Candidate profile not found' }, 404)
    }

    const { Password, ...safeData } = candidateDoc
    return c.json({ success: true, candidate: { id: candidateDoc.id, ...safeData } })
  } catch (err: any) {
    return c.json({ error: `Error fetching profile: ${err.message}` }, 500)
  }
}

app.get('/api/candidate/me', candidateAuthMiddleware, handleCandidateProfileGet)
app.get('/api/candidate/profile', candidateAuthMiddleware, handleCandidateProfileGet)

const handleCandidateProfilePut = async (c: any) => {
  try {
    const jwtPayload = c.get('jwtPayload')
    const updateFields = await c.req.json()

    delete updateFields.Password
    delete updateFields.Email
    delete updateFields.RegNo
    updateFields.updatedAt = new Date().toISOString()

    const ok = await updateFirestoreDoc('registrations', jwtPayload.id, updateFields, c.env)
    if (!ok) return c.json({ error: 'Failed to update profile' }, 500)

    const updatedDoc = await getFirestoreDoc('registrations', jwtPayload.id, c.env)
    const { Password, ...safeData } = updatedDoc || {}

    return c.json({ success: true, candidate: { id: jwtPayload.id, ...safeData } })
  } catch (err: any) {
    return c.json({ error: `Update failed: ${err.message}` }, 500)
  }
}

app.put('/api/candidate/me', candidateAuthMiddleware, handleCandidateProfilePut)
app.put('/api/candidate/profile', candidateAuthMiddleware, handleCandidateProfilePut)

// Candidate Change Password Endpoint
app.put('/api/candidate/change-password', candidateAuthMiddleware, async (c: any) => {
  try {
    const jwtPayload = c.get('jwtPayload')
    const { currentPassword, newPassword } = await c.req.json()

    if (!currentPassword || !newPassword) {
      return c.json({ error: 'Current password and new password are required' }, 400)
    }
    if (String(newPassword).length < 6) {
      return c.json({ error: 'New password must be at least 6 characters long' }, 400)
    }

    const candidateDoc = await getFirestoreDoc('registrations', jwtPayload.id, c.env)
    if (!candidateDoc) {
      return c.json({ error: 'Candidate profile not found' }, 404)
    }

    if (!verifyPassword(String(currentPassword).trim(), candidateDoc.Password || '')) {
      return c.json({ error: 'Current password is incorrect' }, 400)
    }

    const newHashed = hashPassword(String(newPassword).trim())
    await updateFirestoreDoc('registrations', jwtPayload.id, { Password: newHashed, updatedAt: new Date().toISOString() }, c.env)

    return c.json({ success: true, message: 'Password updated successfully' })
  } catch (err: any) {
    return c.json({ error: `Change password failed: ${err.message}` }, 500)
  }
})

// Forgot & Reset Password Endpoints
app.post('/api/auth/forgot-password', async (c) => {
  try {
    const { identifier } = await c.req.json()
    if (!identifier) {
      return c.json({ error: 'Email or Registration Number is required' }, 400)
    }

    const cleanInput = String(identifier).trim()
    const cleanInputLower = cleanInput.toLowerCase()

    let targetEmail = ''
    let targetName = 'User'
    let userType = 'candidate'
    let targetDocId = ''

    const emailDocs = await queryFirestore('registrations', 'Email', cleanInputLower, c.env)
    if (emailDocs.length > 0) {
      targetEmail = emailDocs[0].Email
      targetName = emailDocs[0].Name || 'Candidate'
      targetDocId = emailDocs[0].id
    } else {
      const regDocs = await queryFirestore('registrations', 'RegNo', cleanInput, c.env)
      if (regDocs.length > 0) {
        targetEmail = regDocs[0].Email
        targetName = regDocs[0].Name || 'Candidate'
        targetDocId = regDocs[0].id
      }
    }

    if (!targetEmail) {
      return c.json({ error: 'No registered user found with that Email or Registration Number.' }, 404)
    }

    const token = crypto.randomBytes(32).toString('hex')
    const expiresAt = Date.now() + 3600000

    await addFirestoreDoc('password_resets', {
      email: targetEmail,
      userType,
      targetDocId,
      token,
      used: false,
      expiresAt,
      createdAt: new Date().toISOString()
    }, c.env)

    const frontendUrl = c.env.FRONTEND_URL || process.env.FRONTEND_URL || 'https://www.endeavoursliet.in'
    const resetLink = `${frontendUrl}/pages/reset-password?token=${token}`

    if (c.executionCtx) {
      c.executionCtx.waitUntil(
        sendEmailViaGmailRest(
          targetEmail,
          'Password Reset Link - Endeavour SLIET',
          `<h2>Password Reset</h2><p>Hello ${targetName},</p><p>Click the link below to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p>`,
          c.env
        ).catch(() => {})
      )
    }

    return c.json({ success: true, message: `Password reset link sent to ${targetEmail}` })
  } catch (err: any) {
    return c.json({ error: `Forgot password failed: ${err.message}` }, 500)
  }
})

app.get('/api/auth/validate-reset-token', async (c) => {
  try {
    const token = c.req.query('token')
    if (!token) {
      return c.json({ valid: false, error: 'Token query parameter is required' }, 400)
    }

    const docs = await queryFirestore('password_resets', 'token', token, c.env)
    if (docs.length === 0) {
      return c.json({ valid: false, error: 'Password reset link is invalid.' })
    }

    const resetData = docs[0]
    if (resetData.used) {
      return c.json({ valid: false, error: 'This password reset link has already been used.' })
    }

    if (Number(resetData.expiresAt) < Date.now()) {
      return c.json({ valid: false, error: 'This password reset link has expired.' })
    }

    return c.json({ valid: true, email: resetData.email })
  } catch (err: any) {
    return c.json({ valid: false, error: err.message })
  }
})

app.post('/api/auth/reset-password', async (c) => {
  try {
    const { token, newPassword } = await c.req.json()
    if (!token || !newPassword) {
      return c.json({ error: 'Token and new password are required' }, 400)
    }
    if (String(newPassword).length < 6) {
      return c.json({ error: 'Password must be at least 6 characters long' }, 400)
    }

    const docs = await queryFirestore('password_resets', 'token', token, c.env)
    if (docs.length === 0) {
      return c.json({ error: 'Password reset link is invalid.' }, 400)
    }

    const resetDoc = docs[0]
    if (resetDoc.used) {
      return c.json({ error: 'This password reset link has already been used.' }, 400)
    }

    if (Number(resetDoc.expiresAt) < Date.now()) {
      return c.json({ error: 'This password reset link has expired.' }, 400)
    }

    const newHashed = hashPassword(String(newPassword).trim())
    await updateFirestoreDoc('registrations', resetDoc.targetDocId, { Password: newHashed, updatedAt: new Date().toISOString() }, c.env)
    await updateFirestoreDoc('password_resets', resetDoc.id, { used: true, usedAt: new Date().toISOString() }, c.env)

    return c.json({ success: true, message: 'Password reset successful!' })
  } catch (err: any) {
    return c.json({ error: `Reset password failed: ${err.message}` }, 500)
  }
})

// Admin Auth Login Endpoint
app.post('/api/admin/login', async (c) => {
  try {
    const { email, password } = await c.req.json()
    const adminEmail = c.env.ADMIN_EMAIL || process.env.ADMIN_EMAIL || 'admin@endeavoursliet.org'
    const adminPass = c.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || 'admin123'

    const cleanInputEmail = String(email || '').trim().toLowerCase()
    const cleanInputPass = String(password || '').trim()

    let isAdminValid = false
    if (cleanInputEmail === adminEmail.toLowerCase() && cleanInputPass === adminPass) {
      isAdminValid = true
    } else {
      const adminDocs = await queryFirestore('admin_users', 'email', cleanInputEmail, c.env)
      if (adminDocs.length > 0 && verifyPassword(cleanInputPass, adminDocs[0].password)) {
        isAdminValid = true
      }
    }

    if (!isAdminValid) {
      return c.json({ error: 'Invalid admin credentials' }, 401)
    }

    const jwtSecret = c.env.JWT_SECRET || process.env.JWT_SECRET || 'endeavour_secret_key_2025'
    const token = await sign({ email: cleanInputEmail, role: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 }, jwtSecret, 'HS256')

    return c.json({ success: true, token })
  } catch (err: any) {
    return c.json({ error: `Admin login failed: ${err.message}` }, 500)
  }
})

// Admin List Registrations Endpoint
app.get('/api/admin/registrations', adminAuthMiddleware, async (c: any) => {
  try {
    const docs = await listFirestoreDocs('registrations', c.env)
    const formatted = docs.map(doc => {
      const { Password, ...safe } = doc
      return { id: doc.id, ...safe }
    })
    return c.json({ success: true, registrations: formatted })
  } catch (err: any) {
    return c.json({ error: `Fetch error: ${err.message}` }, 500)
  }
})

// Admin Single Delete Endpoint
app.delete('/api/admin/registrations/:id', adminAuthMiddleware, async (c: any) => {
  try {
    const docId = c.req.param('id')
    const ok = await deleteFirestoreDoc('registrations', docId, c.env)
    if (!ok) return c.json({ error: 'Failed to delete record' }, 500)
    return c.json({ success: true, message: 'Record deleted successfully' })
  } catch (err: any) {
    return c.json({ error: `Delete failed: ${err.message}` }, 500)
  }
})

// Admin Batch Delete Endpoint (Fixes "Unexpected non-whitespace character after JSON")
app.post('/api/admin/registrations/batch-delete', adminAuthMiddleware, async (c: any) => {
  try {
    const body = await c.req.json()
    const ids: string[] = Array.isArray(body?.ids) ? body.ids : []

    if (ids.length === 0) {
      return c.json({ error: 'No candidate IDs provided for batch delete' }, 400)
    }

    let deletedCount = 0
    for (const id of ids) {
      const ok = await deleteFirestoreDoc('registrations', id, c.env)
      if (ok) deletedCount++
    }

    return c.json({
      success: true,
      message: `Successfully deleted ${deletedCount} candidate record(s).`
    })
  } catch (err: any) {
    return c.json({ error: `Batch delete failed: ${err.message}` }, 500)
  }
})

// Admin Batch Resend Email Endpoint
app.post('/api/admin/registrations/batch-resend-email', adminAuthMiddleware, async (c: any) => {
  try {
    const body = await c.req.json()
    const ids: string[] = Array.isArray(body?.ids) ? body.ids : []

    if (ids.length === 0) {
      return c.json({ error: 'No candidate IDs provided for batch resend' }, 400)
    }

    let sentCount = 0
    for (const id of ids) {
      const doc = await getFirestoreDoc('registrations', id, c.env)
      if (doc && doc.Email) {
        const rawPassword = crypto.randomBytes(4).toString('hex').toLowerCase()
        const newHashed = hashPassword(rawPassword)
        await updateFirestoreDoc('registrations', id, { Password: newHashed }, c.env)

        if (c.executionCtx) {
          c.executionCtx.waitUntil(
            sendEmailViaGmailRest(
              doc.Email,
              'Endeavour SLIET Candidate Login Credentials',
              `<h1>Welcome ${doc.Name || 'Candidate'}!</h1><p>Your candidate login credentials password is: <strong>${rawPassword}</strong></p>`,
              c.env
            ).catch(() => {})
          )
        }
        sentCount++
      }
    }

    return c.json({ success: true, message: `Dispatched credentials emails to ${sentCount} candidate(s).` })
  } catch (err: any) {
    return c.json({ error: `Batch resend email failed: ${err.message}` }, 500)
  }
})

// Admin Update Candidate Marks Endpoint
app.put('/api/admin/registrations/:id/marks', adminAuthMiddleware, async (c: any) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    body.updatedAt = new Date().toISOString()

    const ok = await updateFirestoreDoc('registrations', id, body, c.env)
    if (!ok) return c.json({ error: 'Failed to update marks' }, 500)

    const updatedDoc = await getFirestoreDoc('registrations', id, c.env)
    return c.json({ success: true, candidate: updatedDoc })
  } catch (err: any) {
    return c.json({ error: `Update marks failed: ${err.message}` }, 500)
  }
})

// Admin Update Candidate Status Endpoint
app.put('/api/admin/registrations/:id/status', adminAuthMiddleware, async (c: any) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const { status } = body

    if (!status) return c.json({ error: 'Status is required' }, 400)

    const ok = await updateFirestoreDoc('registrations', id, { status, updatedAt: new Date().toISOString() }, c.env)
    if (!ok) return c.json({ error: 'Failed to update status' }, 500)

    const updatedDoc = await getFirestoreDoc('registrations', id, c.env)
    return c.json({ success: true, candidate: updatedDoc })
  } catch (err: any) {
    return c.json({ error: `Update status failed: ${err.message}` }, 500)
  }
})

// Admin Resend Email Endpoint
app.post('/api/admin/registrations/:id/resend-email', adminAuthMiddleware, async (c: any) => {
  try {
    const id = c.req.param('id')
    const doc = await getFirestoreDoc('registrations', id, c.env)
    if (!doc || !doc.Email) {
      return c.json({ error: 'Candidate record or Email not found' }, 404)
    }

    const rawPassword = crypto.randomBytes(4).toString('hex').toLowerCase()
    const newHashed = hashPassword(rawPassword)
    await updateFirestoreDoc('registrations', id, { Password: newHashed, emailSent: true }, c.env)

    if (c.executionCtx) {
      c.executionCtx.waitUntil(
        sendEmailViaGmailRest(
          doc.Email,
          'Endeavour SLIET Candidate Login Credentials',
          `<h1>Welcome ${doc.Name || 'Candidate'}!</h1><p>Your candidate login credentials password is: <strong>${rawPassword}</strong></p>`,
          c.env
        ).catch(() => {})
      )
    }

    return c.json({ success: true, message: `Credentials email resent to ${doc.Email}` })
  } catch (err: any) {
    return c.json({ error: `Resend email failed: ${err.message}` }, 500)
  }
})

// Background Helper: Sync offline Google Sheet fallback entries into Firestore & send email credentials
async function syncOfflineRegistrations(env: Bindings): Promise<number> {
  const scriptUrl = (env.GOOGLE_SCRIPT_URL || env.RECOVERY_GOOGLE_SCRIPT_URL || process.env.GOOGLE_SCRIPT_URL || '').trim()
  if (!scriptUrl) return 0

  let syncedCount = 0
  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 45000)

    const response = await fetch(`${scriptUrl}${scriptUrl.includes('?') ? '&' : '?'}action=getUnsyncedRecords`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      },
      redirect: 'follow',
      signal: controller.signal
    }).finally(() => clearTimeout(timeoutId))

    if (!response.ok) return syncedCount
    const text = await response.text()
    if (!text || text.includes('<!DOCTYPE html>') || text.includes('Script function not found')) {
      return syncedCount
    }

    let data: any = {}
    try { data = JSON.parse(text) } catch { return syncedCount }

    const records = Array.isArray(data) ? data : (data?.records || [])
    if (!Array.isArray(records) || records.length === 0) return syncedCount

    const processedEmails = new Set<string>()

    for (const record of records) {
      const cleanEmail = String(record.Email || record.email || '').trim().toLowerCase()
      const cleanRegNo = String(record.RegNo || record.regNo || '').trim()
      if (!cleanEmail || !cleanRegNo) continue
      if (processedEmails.has(cleanEmail)) continue
      processedEmails.add(cleanEmail)

      const markRecordSynced = () => {
        fetch(`${scriptUrl}?action=markSynced&email=${encodeURIComponent(cleanEmail)}&regNo=${encodeURIComponent(cleanRegNo)}`, {
          method: 'POST',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
          }
        }).catch(() => {})
      }

      const emailDocs = await queryFirestore('registrations', 'Email', cleanEmail, env)
      const regDocs = await queryFirestore('registrations', 'RegNo', cleanRegNo, env)

      if (emailDocs.length > 0 || regDocs.length > 0) {
        console.log(`ℹ️ [Worker Sync] Registration for ${cleanEmail} (${cleanRegNo}) already in Firestore. Marking synced in Sheet.`)
        markRecordSynced()
        continue
      }

      const rawPassword = record.Password || crypto.randomBytes(4).toString('hex').toLowerCase()
      const newRecord = {
        ...record,
        Email: cleanEmail,
        RegNo: cleanRegNo,
        Password: hashPassword(rawPassword),
        submittedAt: record.submittedAt || new Date().toISOString(),
        status: record.status || 'pending',
        syncedFromOffline: true
      }

      const docId = await addFirestoreDoc('registrations', newRecord, env)
      console.log(`✅ [Worker Sync] Restored offline registration for ${cleanEmail} to Firestore (Doc: ${docId}).`)
      syncedCount++

      markRecordSynced()

      await sendEmailViaGmailRest(
        cleanEmail,
        'Welcome to Endeavour 2026 - Registration Confirmed',
        `<h1>Welcome ${record.Name || 'Candidate'}!</h1><p>Your registration is confirmed. Your candidate portal login password is: <strong>${rawPassword}</strong></p>`,
        env
      ).catch((e) => console.error(`Worker sync email dispatch failed for ${cleanEmail}:`, e))
    }
  } catch (err: any) {
    console.warn(`[Worker Sync] Warning:`, err.message || err)
  }

  return syncedCount
}

// Endpoint to trigger manual sync of offline Google Sheet records
app.post('/api/admin/sync-offline', async (c) => {
  try {
    const synced = await syncOfflineRegistrations(c.env)
    return c.json({ success: true, message: `Offline sync completed. ${synced} record(s) restored.` })
  } catch (e: any) {
    return c.json({ error: `Sync failed: ${e.message}` }, 500)
  }
})

export default {
  fetch(request: Request, env: Bindings, ctx: any) {
    return app.fetch(request, env, ctx)
  },
  async scheduled(event: any, env: Bindings, ctx: any) {
    ctx.waitUntil(syncOfflineRegistrations(env))
  }
}
