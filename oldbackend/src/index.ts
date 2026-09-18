import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { db } from './config/firebase.js'
import { uploadToCloudinary } from './config/cloudinary.js'
import { sendRegistrationEmail, sendAdminCredentialsEmail, sendStageNotificationEmail, sendPasswordResetEmail, sendCandidateCredentialsEmail, sendCustomEmail } from './config/mail.js'
import { pushEmailJob } from './config/redisQueue.js'
import { sign, verify } from 'hono/jwt'
import { adminAuthMiddleware } from './middleware/auth.js'
import crypto from 'crypto'
import dotenv from 'dotenv'

dotenv.config()

// Password Hashing & Security Helper Functions (PBKDF2 SHA-512)
function hashPassword(password: string): string {
  if (!password) return ''
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex')
  return `${salt}:${hash}`
}

function verifyPassword(password: string, storedHash: string): boolean {
  if (!password || !storedHash) return false

  // Backward compatibility check for unhashed plain text legacy passwords
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

// Extract clean unhashed plain text password for emails, or generate fresh plain password if hash stored
function getCleanPasswordForEmail(storedPassword: any, regNo: any): { pwdForEmail: string, newHashedPassword?: string } {
  const pwdStr = String(storedPassword || '').trim()

  if (!pwdStr) {
    const fallback = String(regNo || '123456').trim()
    return { pwdForEmail: fallback, newHashedPassword: hashPassword(fallback) }
  }

  if (pwdStr.includes(':')) {
    const freshPlainPwd = crypto.randomBytes(4).toString('hex').toLowerCase()
    return { pwdForEmail: freshPlainPwd, newHashedPassword: hashPassword(freshPlainPwd) }
  }

  return { pwdForEmail: pwdStr }
}

const candidateAuthMiddleware = () => {
  return async (c: any, next: any) => {
    const authHeader = c.req.header('Authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized: Missing or invalid token' }, 401)
    }
    const token = authHeader.split(' ')[1]
    const jwtSecret = process.env.JWT_SECRET || 'endeavour_secret_key_2025'
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
}

const app = new Hono()

// Enable CORS for frontend requests including Vercel & Private Network Access (PNA)
app.use('*', cors({
  origin: (origin) => origin || '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'Access-Control-Allow-Private-Network'],
  exposeHeaders: ['Content-Length'],
  maxAge: 600,
  credentials: true,
}))

// PNA (Private Network Access) preflight response header
app.use('*', async (c, next) => {
  c.header('Access-Control-Allow-Private-Network', 'true')
  await next()
})

app.get('/', (c) => {
  return c.json({
    message: 'Hello Hono Backend!',
    status: 'operational',
  })
})

// Route for handling file uploads (Photo/Resume) to Cloudinary
app.post('/api/upload', async (c) => {
  try {
    const body = await c.req.parseBody()
    const file = body.file
    const type = body.type // 'photo' or 'resume'

    if (!file || !(file instanceof File)) {
      return c.json({ error: 'No file uploaded' }, 400)
    }

    const folder = type === 'photo' ? 'endeavour/photos' : 'endeavour/resumes'
    const resourceType = type === 'photo' ? 'image' : 'raw'
    const url = await uploadToCloudinary(file, folder, resourceType)
    return c.json({ success: true, url })
  } catch (err: any) {
    console.error('File upload error:', err)
    return c.json({ error: `Upload failed: ${err.message}` }, 500)
  }
})

// Route for saving registration details to Firebase and Google Sheets
app.post('/api/register', async (c) => {
  try {
    const registrationData = await c.req.json()

    // Enforce registrations toggle status
    if (db) {
      try {
        const settingsDoc = await db.collection('settings').doc('general').get()
        if (settingsDoc.exists && settingsDoc.data()?.registrationEnabled === false) {
          return c.json({ error: 'Registrations are currently closed.' }, 403)
        }
      } catch (e) {
        console.error('Failed to verify registration toggle status:', e)
      }
    }

    // Basic validation
    const { Name, Email, Contact, RegNo, Photo, Password } = registrationData
    if (!Name || !Email || !Contact || !RegNo) {
      return c.json({ error: 'Missing required fields' }, 400)
    }
    if (!Photo) {
      return c.json({ error: 'Photo URL is required' }, 400)
    }

    // Duplicate Email and RegNo Check in Firestore
    if (db) {
      const cleanEmail = String(Email).trim()
      const cleanRegNo = String(RegNo).trim()

      const emailSnap = await db.collection('registrations').where('Email', '==', cleanEmail).get()
      if (!emailSnap.empty) {
        return c.json({ error: `Already registered with this Email or Registration Number. Please login using your Email / RegNo and Password.` }, 400)
      }
      const regSnap = await db.collection('registrations').where('RegNo', '==', cleanRegNo).get()
      if (!regSnap.empty) {
        return c.json({ error: `Already registered with this Email or Registration Number. Please login using your Email / RegNo and Password.` }, 400)
      }
    }

    // Add metadata & assign auto-generated random password (8-char alphanumeric)
    const rawPassword = Password && String(Password).trim()
      ? String(Password).trim()
      : crypto.randomBytes(4).toString('hex').toLowerCase()

    // Store encrypted password in database
    registrationData.Password = hashPassword(rawPassword)
    registrationData.submittedAt = new Date().toISOString()
    registrationData.status = 'pending'

    // 1. Save to Firebase Firestore (if configured)
    let firebaseSaved = false
    let docRefId = ''
    if (db) {
      try {
        const docRef = await db.collection('registrations').add(registrationData)
        docRefId = docRef.id
        firebaseSaved = true
      } catch (err) {
        console.error('Firebase Firestore save error:', err)
      }
    } else {
      console.warn('Firebase DB not initialized. Skipping save.')
    }

    // 2. Save to Google Sheets via Webhook
    let googleSheetSaved = false
    const googleScriptUrl = process.env.GOOGLE_SCRIPT_URL
    if (googleScriptUrl) {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 4000)

      try {
        const gFormData = new FormData()
        Object.entries(registrationData).forEach(([key, val]) => {
          if (val !== undefined && val !== null) {
            gFormData.append(key, String(val))
          }
        })

        const response = await fetch(googleScriptUrl, {
          method: 'POST',
          body: gFormData,
          signal: controller.signal
        })
        clearTimeout(timeoutId)
        if (response.ok) {
          googleSheetSaved = true
        } else {
          console.error(`Google Sheet endpoint returned status ${response.status}`)
        }
      } catch (err: any) {
        clearTimeout(timeoutId)
        if (err.name === 'AbortError') {
          console.warn('Google Sheets sync connection timed out (4000ms). Skipping Google Sheet sync.')
        } else {
          console.error('Google Sheets submission error:', err.message || err)
        }
      }
    } else {
      console.warn('Google Script URL not configured. Skipping save.')
    }

    // Check if at least one save succeeded
    if (!firebaseSaved && !googleSheetSaved) {
      return c.json({ error: 'Failed to save registration data to both databases' }, 500)
    }

    // 3. Dispatch registration confirmation & login credentials emails asynchronously in background
    pushEmailJob({
      id: docRefId || String(RegNo),
      type: 'registration_and_credentials',
      email: String(Email),
      name: String(Name),
      regNo: String(RegNo),
      password: rawPassword,
      timestamp: new Date().toISOString()
    }).catch(err => console.error('Background email job error:', err))

    return c.json({
      success: true,
      message: 'Registration successful!',
      data: {
        firebaseSaved,
        googleSheetSaved,
      },
    })
  } catch (err: any) {
    console.error('Registration processing error:', err)
    return c.json({ error: `Internal server error: ${err.message}` }, 500)
  }
})

// Admin login route
app.post('/api/admin/login', async (c) => {
  try {
    const { email, password } = await c.req.json()
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@endeavoursliet.org'
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123'
    const jwtSecret = process.env.JWT_SECRET || 'endeavour_secret_key_2025'

    let isSuperAdmin = false
    let adminName = 'Super Admin'

    if (email === adminEmail && password === adminPassword) {
      isSuperAdmin = true
    } else {
      // Check database custom admin credentials
      if (!db) {
        return c.json({ error: 'Database not initialized' }, 500)
      }

      const adminDoc = await db.collection('admins').doc(email).get()
      if (!adminDoc.exists || !verifyPassword(password, adminDoc.data()?.password)) {
        return c.json({ error: 'Invalid email or password' }, 401)
      }

      adminName = adminDoc.data()?.name || 'Admin'
    }

    // Sign JWT token valid for 24 hours (Include role claim for middleware validation)
    const token = await sign(
      {
        email,
        name: adminName,
        isSuperAdmin,
        role: isSuperAdmin ? 'superadmin' : 'admin',
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      },
      jwtSecret
    )

    return c.json({ success: true, token })
  } catch (err: any) {
    console.error('Admin login error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Protected route to fetch all registrations
app.get('/api/admin/registrations', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Firebase Firestore database is not configured' }, 500)
    }

    const snapshot = await db.collection('registrations').orderBy('submittedAt', 'desc').get()
    const registrations = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }))

    return c.json({ success: true, registrations })
  } catch (err: any) {
    console.error('Fetch registrations error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Protected route to update registration status
app.put('/api/admin/registrations/:id/status', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Firebase Firestore database is not configured' }, 500)
    }

    const id = c.req.param('id')
    const { status } = await c.req.json()

    if (!['pending', 'approved', 'rejected', 'interview'].includes(status)) {
      return c.json({ error: 'Invalid status value' }, 400)
    }

    await db.collection('registrations').doc(id).update({ status })

    return c.json({ success: true, message: 'Status updated successfully' })
  } catch (err: any) {
    console.error('Update status error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Endpoint to resend registration & credentials emails to a candidate (non-blocking)
app.post('/api/admin/registrations/:id/resend-email', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const id = c.req.param('id')
    const docRef = db.collection('registrations').doc(id)
    const doc = await docRef.get()

    if (!doc.exists) {
      return c.json({ error: 'Candidate registration record not found' }, 404)
    }

    const data = doc.data() || {}
    const { Email, Name, RegNo, Password } = data

    if (!Email) {
      return c.json({ error: 'Candidate has no valid email address' }, 400)
    }

    const { pwdForEmail, newHashedPassword } = getCleanPasswordForEmail(Password, RegNo)

    // Mark status as Pending in database immediately and update Password hash if regenerated
    const updateFields: any = { emailSent: null, emailError: null, lastEmailAttemptAt: new Date().toISOString() }
    if (newHashedPassword) {
      updateFields.Password = newHashedPassword
    }
    await docRef.set(updateFields, { merge: true })

    // Fire background non-blocking email job
    pushEmailJob({
      id,
      type: 'registration_and_credentials',
      email: String(Email),
      name: String(Name || 'Candidate'),
      regNo: String(RegNo || ''),
      password: pwdForEmail,
      timestamp: new Date().toISOString()
    })

    return c.json({ success: true, message: 'Email dispatch started in background!' })
  } catch (err: any) {
    console.error('Resend email error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Endpoint to batch resend registration & credentials emails to multiple selected candidates (non-blocking)
app.post('/api/admin/registrations/batch-resend-email', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const { ids } = await c.req.json()

    if (!Array.isArray(ids) || ids.length === 0) {
      return c.json({ error: 'No candidate IDs provided for batch email resend' }, 400)
    }

    // Process all candidate email dispatches in background non-blocking loop
    (async () => {
      for (const id of ids) {
        try {
          const docRef = db.collection('registrations').doc(id)
          const doc = await docRef.get()
          if (!doc.exists) continue

          const data = doc.data() || {}
          const { Email, Name, RegNo, Password } = data
          if (!Email) continue

          const { pwdForEmail, newHashedPassword } = getCleanPasswordForEmail(Password, RegNo)

          // Mark status as pending and update Password hash if regenerated
          const updateFields: any = { emailSent: null, emailError: null, lastEmailAttemptAt: new Date().toISOString() }
          if (newHashedPassword) {
            updateFields.Password = newHashedPassword
          }
          await docRef.set(updateFields, { merge: true })

          await pushEmailJob({
            id,
            type: 'registration_and_credentials',
            email: String(Email),
            name: String(Name || 'Candidate'),
            regNo: String(RegNo || ''),
            password: pwdForEmail,
            timestamp: new Date().toISOString()
          })
        } catch (e) {
          console.error(`Batch resend error for candidate ${id}:`, e)
        }
      }
    })()

    return c.json({
      success: true,
      message: `Batch email dispatch started in background for ${ids.length} candidates. Statuses will update automatically.`
    })
  } catch (err: any) {
    console.error('Batch resend emails error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Endpoint to send custom email to single, selected, or all candidates (non-blocking)
app.post('/api/admin/send-custom-email', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const { target, ids, subject, messageHtml } = await c.req.json()

    if (!subject || !messageHtml) {
      return c.json({ error: 'Subject and message body are required' }, 400)
    }

    let recipients: Array<{ id?: string, email: string, name?: string }> = []

    if (target === 'single' && ids && ids.length > 0) {
      const doc = await db.collection('registrations').doc(ids[0]).get()
      if (doc.exists && doc.data()?.Email) {
        recipients.push({ id: doc.id, email: doc.data()?.Email, name: doc.data()?.Name })
      }
    } else if (target === 'selected' && Array.isArray(ids) && ids.length > 0) {
      const snapshot = await db.collection('registrations').get()
      snapshot.docs.forEach(doc => {
        if (ids.includes(doc.id) && doc.data()?.Email) {
          recipients.push({ id: doc.id, email: doc.data()?.Email, name: doc.data()?.Name })
        }
      })
    } else if (target === 'all') {
      const snapshot = await db.collection('registrations').get()
      snapshot.docs.forEach(doc => {
        if (doc.data()?.Email) {
          recipients.push({ id: doc.id, email: doc.data()?.Email, name: doc.data()?.Name })
        }
      })
    }

    if (recipients.length === 0) {
      return c.json({ error: 'No valid recipient email addresses found' }, 400)
    }

    // Fire background non-blocking custom email dispatch loop
    (async () => {
      for (const recipient of recipients) {
        try {
          await pushEmailJob({
            id: recipient.id || '',
            type: 'custom_email',
            email: recipient.email,
            name: recipient.name || 'Candidate',
            subject,
            messageHtml,
            timestamp: new Date().toISOString()
          })
        } catch (e) {
          console.error(`Custom email dispatch error for ${recipient.email}:`, e)
        }
      }
    })()

    return c.json({
      success: true,
      message: `Custom email dispatch started in background for ${recipients.length} recipients.`
    })
  } catch (err: any) {
    console.error('Send custom email error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Endpoint to import Excel stage marks with conflict detection & history backup
app.post('/api/admin/marks/import', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const { items, forceOverwrite } = await c.req.json()

    if (!Array.isArray(items) || items.length === 0) {
      return c.json({ error: 'No valid data rows provided for import' }, 400)
    }

    const snapshot = await db.collection('registrations').get()
    const allDocs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }))

    const conflicts: any[] = []
    const updatesToApply: any[] = []

    for (const item of items) {
      const cleanReg = String(item.regNo || item.RegNo || item['Reg No'] || '').trim().toLowerCase()
      if (!cleanReg) continue

      const match: any = allDocs.find((doc: any) => String(doc.RegNo || '').trim().toLowerCase() === cleanReg)
      if (!match) continue

      const hasExistingMarks = (match.marksAptitude !== undefined && match.marksAptitude !== null && match.marksAptitude !== '') ||
        (match.marksInterview !== undefined && match.marksInterview !== null && match.marksInterview !== '') ||
        (match.marksClassInterview !== undefined && match.marksClassInterview !== null && match.marksClassInterview !== '')

      const newAptitude = item.aptitudeMarks !== undefined && item.aptitudeMarks !== null && item.aptitudeMarks !== '' ? Number(item.aptitudeMarks) : null
      const newInterview = item.interviewMarks !== undefined && item.interviewMarks !== null && item.interviewMarks !== '' ? Number(item.interviewMarks) : null
      const newClass = item.classMarks !== undefined && item.classMarks !== null && item.classMarks !== '' ? Number(item.classMarks) : null

      if (hasExistingMarks && !forceOverwrite) {
        conflicts.push({
          id: match.id,
          regNo: match.RegNo,
          name: match.Name,
          oldMarks: {
            aptitude: match.marksAptitude ?? 'N/A',
            interview: match.marksInterview ?? 'N/A',
            class: match.marksClassInterview ?? 'N/A'
          },
          newMarks: {
            aptitude: newAptitude ?? 'N/A',
            interview: newInterview ?? 'N/A',
            class: newClass ?? 'N/A'
          }
        })
      }

      updatesToApply.push({
        id: match.id,
        existingData: match,
        hasExistingMarks,
        newAptitude,
        newInterview,
        newClass
      })
    }

    if (conflicts.length > 0 && !forceOverwrite) {
      return c.json({
        requiresConfirmation: true,
        conflictsCount: conflicts.length,
        conflicts
      })
    }

    let updatedCount = 0

    const payload = c.get('jwtPayload') as any
    const adminIdentifier = (payload?.isSuperAdmin || payload?.name === 'Super Admin')
      ? 'Super Admin'
      : (payload?.name ? `${payload.name} (${payload.email})` : (payload?.email || 'Sub Admin'))

    for (const update of updatesToApply) {
      const docRef = db.collection('registrations').doc(update.id)
      const updateData: any = {}

      if (update.newAptitude !== null) updateData.marksAptitude = update.newAptitude
      if (update.newInterview !== null) updateData.marksInterview = update.newInterview
      if (update.newClass !== null) updateData.marksClassInterview = update.newClass

      const historyEntry = {
        timestamp: new Date().toISOString(),
        updatedBy: adminIdentifier,
        updateMethod: 'Excel Import',
        previousMarks: {
          marksAptitude: update.existingData.marksAptitude ?? null,
          marksInterview: update.existingData.marksInterview ?? null,
          marksClassInterview: update.existingData.marksClassInterview ?? null
        },
        newMarks: {
          marksAptitude: update.newAptitude ?? update.existingData.marksAptitude ?? null,
          marksInterview: update.newInterview ?? update.existingData.marksInterview ?? null,
          marksClassInterview: update.newClass ?? update.existingData.marksClassInterview ?? null
        }
      }

      const existingHistory = Array.isArray(update.existingData.marksHistory) ? update.existingData.marksHistory : []
      updateData.marksHistory = [historyEntry, ...existingHistory]
      updateData.lastUpdatedBy = `${adminIdentifier} (Excel Import)`
      updateData.lastUpdatedAt = new Date().toISOString()

      await docRef.set(updateData, { merge: true })
      updatedCount++
    }

    return c.json({
      success: true,
      message: `Successfully imported stage marks for ${updatedCount} candidates!`,
      updatedCount
    })
  } catch (err: any) {
    console.error('Import marks error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Endpoint to batch delete multiple candidate registrations
app.post('/api/admin/registrations/batch-delete', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Firebase Firestore database is not configured' }, 500)
    }

    const { ids } = await c.req.json()

    if (!Array.isArray(ids) || ids.length === 0) {
      return c.json({ error: 'No candidate IDs provided for batch deletion' }, 400)
    }

    const batch = db.batch()
    for (const id of ids) {
      const docRef = db.collection('registrations').doc(id)
      batch.delete(docRef)
    }

    await batch.commit()

    return c.json({ success: true, message: `${ids.length} candidates deleted successfully` })
  } catch (err: any) {
    console.error('Batch delete registrations error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Protected route to delete a candidate registration
app.delete('/api/admin/registrations/:id', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Firebase Firestore database is not configured' }, 500)
    }

    const id = c.req.param('id')
    await db.collection('registrations').doc(id).delete()

    return c.json({ success: true, message: 'Registration deleted successfully' })
  } catch (err: any) {
    console.error('Delete registration error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Public endpoint to retrieve portal settings
app.get('/api/settings', async (c) => {
  try {
    if (!db) {
      return c.json({ registrationEnabled: true, allowCandidateUpdates: true, registrationEndDate: '19/09/2025', syllabusFiles: [] })
    }

    const settingsDoc = await db.collection('settings').doc('general').get()
    if (!settingsDoc.exists) {
      return c.json({
        registrationEnabled: true,
        allowCandidateUpdates: true,
        registrationEndDate: '18/09/2026',
        whatsappLink: 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR',
        syllabusLink: '',
        syllabusFiles: [],
        contactDetails: [
          { name: 'Ashutosh Mehta', role: 'Coordinator', phone: '+919027042638' },
          { name: 'Anmol Ranjan', role: 'Coordinator & Treasurer', phone: '+916201957167' }
        ]
      })
    }

    const data = settingsDoc.data() || {}
    return c.json({
      registrationEnabled: data.registrationEnabled !== false,
      allowCandidateUpdates: data.allowCandidateUpdates !== false,
      sendEmailAttachments: data.sendEmailAttachments === true,
      registrationEndDate: data.registrationEndDate || '18/09/2026',
      whatsappLink: data.whatsappLink || 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR',
      syllabusLink: data.syllabusLink || '',
      syllabusFiles: Array.isArray(data.syllabusFiles) ? data.syllabusFiles : [],
      contactDetails: data.contactDetails || []
    })
  } catch (err: any) {
    console.error('Fetch settings error:', err)
    return c.json({ registrationEnabled: true, allowCandidateUpdates: true, sendEmailAttachments: false, registrationEndDate: '18/09/2026', syllabusFiles: [] })
  }
})

// Protected endpoint to update settings (Super Admin only)
app.post('/api/admin/settings', adminAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!payload.isSuperAdmin) {
      return c.json({ error: 'Forbidden: Super Admin access required' }, 403)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const body = await c.req.json()
    const { registrationEnabled, allowCandidateUpdates, sendEmailAttachments, registrationEndDate, whatsappLink, syllabusLink, syllabusFiles, contactDetails } = body

    await db.collection('settings').doc('general').set({
      registrationEnabled: registrationEnabled !== false,
      allowCandidateUpdates: allowCandidateUpdates !== false,
      sendEmailAttachments: sendEmailAttachments === true,
      registrationEndDate: registrationEndDate || '19/09/2025',
      whatsappLink: whatsappLink || '',
      syllabusLink: syllabusLink || '',
      syllabusFiles: Array.isArray(syllabusFiles) ? syllabusFiles : [],
      contactDetails: Array.isArray(contactDetails) ? contactDetails : []
    }, { merge: true })

    return c.json({ success: true, message: 'Settings saved successfully.' })
  } catch (err: any) {
    console.error('Update settings error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Super Admin user management: Get all admins (Super Admin only)
app.get('/api/admin/users', adminAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!payload.isSuperAdmin) {
      return c.json({ error: 'Forbidden: Super Admin access required' }, 403)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const snapshot = await db.collection('admins').get()
    const users = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }))

    return c.json({ success: true, users })
  } catch (err: any) {
    console.error('Fetch admin users error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Super Admin user management: Create admin user (Super Admin only)
app.post('/api/admin/users', adminAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!payload.isSuperAdmin) {
      return c.json({ error: 'Forbidden: Super Admin access required' }, 403)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const { name, email } = await c.req.json()
    if (!name || !email) {
      return c.json({ error: 'Missing name or email' }, 400)
    }

    // Auto-generate random 8-character password
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    let generatedPassword = ''
    for (let i = 0; i < 8; i++) {
      generatedPassword += chars.charAt(Math.floor(Math.random() * chars.length))
    }

    // Save to Firestore admins collection with hashed password
    await db.collection('admins').doc(email).set({
      name,
      email,
      password: hashPassword(generatedPassword),
      role: 'admin',
      createdAt: new Date().toISOString()
    })

    // Send credentials email
    await sendAdminCredentialsEmail(email, name, generatedPassword)

    return c.json({ success: true, message: 'Admin user created and credentials emailed.' })
  } catch (err: any) {
    console.error('Create admin user error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Super Admin user management: Delete admin user (Super Admin only)
app.delete('/api/admin/users/:email', adminAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!payload.isSuperAdmin) {
      return c.json({ error: 'Forbidden: Super Admin access required' }, 403)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const email = c.req.param('email')
    await db.collection('admins').doc(email).delete()

    return c.json({ success: true, message: 'Admin user deleted successfully.' })
  } catch (err: any) {
    console.error('Delete admin user error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Profile management: Update profile name/password (All Admins/Super Admin)
app.put('/api/admin/profile', adminAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    const { name, password } = await c.req.json()
    const jwtSecret = process.env.JWT_SECRET || 'default_secret'

    if (payload.isSuperAdmin) {
      if (password) {
        return c.json({ error: 'Super admin password must be changed in env configuration' }, 400)
      }

      // Super admin can update name (saved in re-issued token)
      const token = await sign(
        {
          email: payload.email,
          name: name || payload.name,
          isSuperAdmin: true,
          exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
        },
        jwtSecret
      )
      return c.json({ success: true, token })
    }

    // Normal Admin profile updates
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const updateFields: any = {}
    if (name) updateFields.name = name
    if (password) updateFields.password = hashPassword(password)

    await db.collection('admins').doc(payload.email).update(updateFields)

    // Re-issue JWT token with updated name
    const token = await sign(
      {
        email: payload.email,
        name: name || payload.name,
        isSuperAdmin: false,
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      },
      jwtSecret
    )

    return c.json({ success: true, token })
  } catch (err: any) {
    console.error('Update profile error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Protected route to save candidate selection stages marks
app.put('/api/admin/registrations/:id/marks', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Firebase Firestore database is not configured' }, 500)
    }

    const id = c.req.param('id')
    const payload = c.get('jwtPayload') as any
    const adminIdentifier = (payload?.isSuperAdmin || payload?.name === 'Super Admin')
      ? 'Super Admin'
      : (payload?.name ? `${payload.name} (${payload.email})` : (payload?.email || 'Sub Admin'))

    const { marksAptitude, marksInterview, marksClassInterview } = await c.req.json()

    const docRef = db.collection('registrations').doc(id)
    const existingDoc = await docRef.get()
    const existingData = existingDoc.exists ? existingDoc.data() || {} : {}

    const newApt = marksAptitude !== undefined && marksAptitude !== '' && marksAptitude !== null ? Number(marksAptitude) : null
    const newInt = marksInterview !== undefined && marksInterview !== '' && marksInterview !== null ? Number(marksInterview) : null
    const newCls = marksClassInterview !== undefined && marksClassInterview !== '' && marksClassInterview !== null ? Number(marksClassInterview) : null

    const historyEntry = {
      timestamp: new Date().toISOString(),
      updatedBy: adminIdentifier,
      updateMethod: 'Manual Edit',
      previousMarks: {
        marksAptitude: existingData.marksAptitude ?? null,
        marksInterview: existingData.marksInterview ?? null,
        marksClassInterview: existingData.marksClassInterview ?? null
      },
      newMarks: {
        marksAptitude: newApt,
        marksInterview: newInt,
        marksClassInterview: newCls
      }
    }

    const existingHistory = Array.isArray(existingData.marksHistory) ? existingData.marksHistory : []

    await docRef.set({
      marksAptitude: newApt,
      marksInterview: newInt,
      marksClassInterview: newCls,
      marksHistory: [historyEntry, ...existingHistory],
      lastUpdatedBy: `${adminIdentifier} (Manual Edit)`,
      lastUpdatedAt: new Date().toISOString()
    }, { merge: true })

    return c.json({ success: true, message: 'Candidate marks saved successfully.' })
  } catch (err: any) {
    console.error('Save candidate marks error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Protected route to send bulk stage notification emails
app.post('/api/admin/notifications/bulk', adminAuthMiddleware(), async (c) => {
  try {
    if (!db) {
      return c.json({ error: 'Firebase Firestore database is not configured' }, 500)
    }

    const { stage, dateTime, venue, instructions } = await c.req.json()
    if (!stage || !dateTime || !venue) {
      return c.json({ error: 'Missing required parameters: stage, dateTime, or venue' }, 400)
    }

    // Retrieve all registered candidates
    const snapshot = await db.collection('registrations').get()
    const candidates = snapshot.docs.map(doc => ({
      email: doc.data().Email,
      name: doc.data().Name
    })).filter(c => c.email && c.name)

    if (candidates.length === 0) {
      return c.json({ success: true, message: 'No registered candidates found to email.', count: 0 })
    }

    // Dispatch nodemailer emails in parallel and await completion to prevent container freeze
    const triggerEmails = async () => {
      const emailPromises = candidates.map(async (candidate) => {
        try {
          await sendStageNotificationEmail(
            candidate.email,
            candidate.name,
            Number(stage),
            dateTime,
            venue,
            instructions || ''
          )
        } catch (e) {
          console.error(`Failed to send bulk stage ${stage} invite to ${candidate.email}:`, e)
        }
      })
      await Promise.all(emailPromises)
    }
    await triggerEmails()

    return c.json({
      success: true,
      message: `Asynchronously sending Stage ${stage} invitation emails to ${candidates.length} candidates.`,
      count: candidates.length
    })
  } catch (err: any) {
    console.error('Send bulk stage notifications error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Candidate Login Endpoint (Authenticates via Email or RegNo and Password)
app.post('/api/candidate/login', async (c) => {
  try {
    const { identifier, password } = await c.req.json()
    if (!identifier || !password) {
      return c.json({ error: 'Email / RegNo and Password are required' }, 400)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const cleanId = String(identifier).trim()
    const cleanIdLower = cleanId.toLowerCase()

    let candidateDoc: any = null
    const emailSnap = await db.collection('registrations').where('Email', '==', cleanId).get()
    if (!emailSnap.empty) {
      candidateDoc = emailSnap.docs[0]
    } else {
      const emailSnapLower = await db.collection('registrations').where('Email', '==', cleanIdLower).get()
      if (!emailSnapLower.empty) {
        candidateDoc = emailSnapLower.docs[0]
      } else {
        const regSnap = await db.collection('registrations').where('RegNo', '==', cleanId).get()
        if (!regSnap.empty) {
          candidateDoc = regSnap.docs[0]
        }
      }
    }

    if (!candidateDoc) {
      return c.json({ error: 'No registered account found with that Email or Registration Number.' }, 404)
    }

    const data = candidateDoc.data()
    const validPassword = data.Password || data.RegNo

    if (!verifyPassword(String(password).trim(), String(validPassword).trim())) {
      return c.json({ error: 'Invalid password. Please check your credentials.' }, 401)
    }

    const jwtSecret = process.env.JWT_SECRET || 'endeavour_secret_key_2025'
    const token = await sign({
      id: candidateDoc.id,
      email: data.Email,
      regNo: data.RegNo,
      name: data.Name,
      role: 'candidate',
      exp: Math.floor(Date.now() / 1000) + 86400 * 7 // 7 days token
    }, jwtSecret)

    return c.json({
      success: true,
      token,
      candidate: {
        id: candidateDoc.id,
        name: data.Name,
        email: data.Email,
        regNo: data.RegNo,
      }
    })
  } catch (err: any) {
    console.error('Candidate login error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Candidate Profile Endpoint (Fetch candidate profile and settings toggle status)
app.get('/api/candidate/profile', candidateAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const doc = await db.collection('registrations').doc(payload.id).get()
    if (!doc.exists) {
      return c.json({ error: 'Candidate profile not found' }, 404)
    }

    let allowUpdates = true
    try {
      const settingsDoc = await db.collection('settings').doc('general').get()
      if (settingsDoc.exists && settingsDoc.data()?.allowCandidateUpdates === false) {
        allowUpdates = false
      }
    } catch (e) { }

    return c.json({
      success: true,
      profile: { id: doc.id, ...doc.data() },
      allowUpdates
    })
  } catch (err: any) {
    console.error('Fetch candidate profile error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Candidate Profile Update Endpoint (Subject to allowCandidateUpdates setting)
app.put('/api/candidate/profile', candidateAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    // Verify if Super Admin has permitted profile updates
    const settingsDoc = await db.collection('settings').doc('general').get()
    if (settingsDoc.exists && settingsDoc.data()?.allowCandidateUpdates === false) {
      return c.json({ error: 'Profile updating has been closed by the Admin.' }, 403)
    }

    const body = await c.req.json()
    const allowedFields = [
      'Name', 'Contact', 'Tenth_Percentage', 'Twelveth_Percentage',
      'Diploma_Percentage', 'Gender', 'Programme', 'Year', 'Branch',
      'Photo', 'Resume', 'Tech/Social_Media', 'Social_Media',
      'Software_Used', 'Social_Media_Sample', 'Caption_Task', 'Why'
    ]

    const docRef = db.collection('registrations').doc(payload.id)
    const existingDoc = await docRef.get()
    const existingData = existingDoc.exists ? existingDoc.data() : {}

    const updates: any = {}
    allowedFields.forEach((field) => {
      if (body[field] !== undefined) {
        updates[field] = body[field]
      }
    })

    updates.updatedAt = new Date().toISOString()
    updates.updateType = 'Profile Update'

    await docRef.set(updates, { merge: true })

    // Sync updated entry to Google Sheets via Webhook
    const googleScriptUrl = process.env.GOOGLE_SCRIPT_URL
    if (googleScriptUrl) {
      const fullUpdatedData = {
        ...existingData,
        ...updates
      }

      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 4000)

      try {
        const gFormData = new FormData()
        Object.entries(fullUpdatedData).forEach(([key, val]) => {
          if (val !== undefined && val !== null) {
            gFormData.append(key, String(val))
          }
        })

        const response = await fetch(googleScriptUrl, {
          method: 'POST',
          body: gFormData,
          signal: controller.signal
        })
        clearTimeout(timeoutId)
        if (response.ok) {
          console.log('Profile update entry successfully synced to Google Sheets.')
        } else {
          console.error(`Google Sheet update sync returned status ${response.status}`)
        }
      } catch (err: any) {
        clearTimeout(timeoutId)
        if (err.name === 'AbortError') {
          console.warn('Google Sheets profile update sync timed out (4000ms). Skipping Google Sheet sync.')
        } else {
          console.error('Google Sheets profile update sync error:', err.message || err)
        }
      }
    }

    return c.json({ success: true, message: 'Profile updated successfully!' })
  } catch (err: any) {
    console.error('Update candidate profile error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Endpoint for candidate to change password inside Candidate Portal
app.put('/api/candidate/change-password', candidateAuthMiddleware(), async (c) => {
  try {
    const payload = c.get('jwtPayload') as any
    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const { currentPassword, newPassword } = await c.req.json()

    if (!currentPassword || !newPassword) {
      return c.json({ error: 'Current password and new password are required' }, 400)
    }

    if (newPassword.length < 6) {
      return c.json({ error: 'New password must be at least 6 characters long' }, 400)
    }

    const docRef = db.collection('registrations').doc(payload.id)
    const doc = await docRef.get()

    if (!doc.exists) {
      return c.json({ error: 'Candidate record not found' }, 404)
    }

    const candidateData = doc.data() || {}
    const actualPassword = candidateData.Password || candidateData.RegNo

    if (!verifyPassword(currentPassword, actualPassword)) {
      return c.json({ error: 'Current password is incorrect' }, 400)
    }

    await docRef.set({ Password: hashPassword(newPassword), passwordUpdatedAt: new Date().toISOString() }, { merge: true })

    return c.json({ success: true, message: 'Password changed successfully!' })
  } catch (err: any) {
    console.error('Change candidate password error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Single-Use Forgot Password Request Endpoint
app.post('/api/auth/forgot-password', async (c) => {
  try {
    const { email } = await c.req.json()
    if (!email) {
      return c.json({ error: 'Email or Registration Number is required' }, 400)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const cleanInput = String(email).trim()
    const cleanInputLower = cleanInput.toLowerCase()

    let targetEmail = ''
    let targetName = ''
    let userType: 'admin' | 'candidate' = 'candidate'
    let targetDocId = ''

    // 1. Search in admin_users
    const adminSnap = await db.collection('admin_users').where('email', '==', cleanInputLower).get()
    if (!adminSnap.empty) {
      const adminData = adminSnap.docs[0].data()
      targetEmail = adminData.email
      targetName = adminData.name || 'Admin'
      userType = 'admin'
      targetDocId = adminSnap.docs[0].id
    } else {
      // 2. Search in registrations by Email or RegNo
      let candDoc: any = null
      const candEmailSnap = await db.collection('registrations').where('Email', '==', cleanInput).get()
      if (!candEmailSnap.empty) {
        candDoc = candEmailSnap.docs[0]
      } else {
        const candEmailLowerSnap = await db.collection('registrations').where('Email', '==', cleanInputLower).get()
        if (!candEmailLowerSnap.empty) {
          candDoc = candEmailLowerSnap.docs[0]
        } else {
          const candRegSnap = await db.collection('registrations').where('RegNo', '==', cleanInput).get()
          if (!candRegSnap.empty) {
            candDoc = candRegSnap.docs[0]
          }
        }
      }

      if (candDoc) {
        const candData = candDoc.data()
        targetEmail = candData.Email
        targetName = candData.Name || 'Candidate'
        userType = 'candidate'
        targetDocId = candDoc.id
      }
    }

    if (!targetEmail) {
      return c.json({ error: 'No registered user or candidate found with that Email or Registration Number.' }, 404)
    }

    // Generate random single-use token valid for 1 hour
    const token = crypto.randomBytes(32).toString('hex')
    const expiresAt = Date.now() + 3600000

    await db.collection('password_resets').add({
      email: targetEmail,
      userType,
      targetDocId,
      token,
      used: false,
      expiresAt,
      createdAt: new Date().toISOString()
    })

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000'
    const resetLink = `${frontendUrl}/pages/reset-password?token=${token}`

    await sendPasswordResetEmail(targetEmail, targetName, resetLink)

    return c.json({ success: true, message: `Password reset link sent to ${targetEmail}` })
  } catch (err: any) {
    console.error('Forgot password error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

// Validate Reset Token Endpoint
app.get('/api/auth/validate-reset-token', async (c) => {
  try {
    const token = c.req.query('token')
    if (!token) {
      return c.json({ valid: false, error: 'Token query parameter is required' }, 400)
    }

    if (!db) {
      return c.json({ valid: false, error: 'Database not initialized' }, 500)
    }

    const snap = await db.collection('password_resets').where('token', '==', token).get()
    if (snap.empty) {
      return c.json({ valid: false, error: 'Password reset link is invalid.' })
    }

    const resetData = snap.docs[0].data()

    if (resetData.used) {
      return c.json({ valid: false, error: 'This password reset link has already been used.' })
    }

    if (resetData.expiresAt < Date.now()) {
      return c.json({ valid: false, error: 'This password reset link has expired.' })
    }

    return c.json({ valid: true, email: resetData.email })
  } catch (err: any) {
    console.error('Validate reset token error:', err)
    return c.json({ valid: false, error: err.message })
  }
})

// Reset Password Endpoint (Marks token used: true so link cannot be reused)
app.post('/api/auth/reset-password', async (c) => {
  try {
    const { token, newPassword } = await c.req.json()
    if (!token || !newPassword) {
      return c.json({ error: 'Token and new password are required' }, 400)
    }
    if (String(newPassword).length < 6) {
      return c.json({ error: 'Password must be at least 6 characters long' }, 400)
    }

    if (!db) {
      return c.json({ error: 'Database not initialized' }, 500)
    }

    const snap = await db.collection('password_resets').where('token', '==', token).get()
    if (snap.empty) {
      return c.json({ error: 'Password reset link is invalid.' }, 400)
    }

    const resetDoc = snap.docs[0]
    const resetData = resetDoc.data()

    if (resetData.used) {
      return c.json({ error: 'This password reset link has already been used and cannot be reused.' }, 400)
    }

    if (resetData.expiresAt < Date.now()) {
      return c.json({ error: 'This password reset link has expired. Please request a new one.' }, 400)
    }

    // Update password in corresponding database with encrypted hash
    if (resetData.userType === 'admin') {
      await db.collection('admin_users').doc(resetData.targetDocId).update({
        password: hashPassword(String(newPassword).trim()),
        updatedAt: new Date().toISOString()
      })
    } else {
      await db.collection('registrations').doc(resetData.targetDocId).update({
        Password: hashPassword(String(newPassword).trim()),
        updatedAt: new Date().toISOString()
      })
    }

    // Mark token as used atomically
    await resetDoc.ref.update({
      used: true,
      usedAt: new Date().toISOString()
    })

    return c.json({ success: true, message: 'Password reset successful! You can now log in with your new password.' })
  } catch (err: any) {
    console.error('Reset password error:', err)
    return c.json({ error: `Server error: ${err.message}` }, 500)
  }
})

export default app
