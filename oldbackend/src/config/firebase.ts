import { initializeApp, getApps, cert } from 'firebase-admin/app'
import { getFirestore, Firestore } from 'firebase-admin/firestore'
import dotenv from 'dotenv'

dotenv.config()

const projectId = process.env.FIREBASE_PROJECT_ID
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL
const privateKey = process.env.FIREBASE_PRIVATE_KEY

let db: Firestore | null = null

if (projectId && clientEmail && privateKey) {
  try {
    if (getApps().length === 0) {
      initializeApp({
        credential: cert({
          projectId,
          clientEmail,
          privateKey: privateKey.replace(/\\n/g, '\n'),
        }),
      })
    }
    db = getFirestore()
    console.log('Firebase Admin SDK initialized successfully.')
  } catch (error) {
    console.error('Error initializing Firebase Admin SDK:', error)
  }
} else {
  console.warn('Firebase Admin credentials missing. Firebase integration disabled.')
}

export { db }
