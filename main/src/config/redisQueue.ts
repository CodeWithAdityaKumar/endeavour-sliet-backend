import { Redis as UpstashRedis } from '@upstash/redis';
import IoRedis from 'ioredis';
import { sendRegistrationEmail, sendCandidateCredentialsEmail, sendCustomEmail } from './mail.js';
import { sendEmailViaMicroservice } from './smtpClient.js';
import { db } from './firebase.js';

let upstashClient: UpstashRedis | null = null;
let ioRedisClient: IoRedis | null = null;

const redisConnString = process.env.REDIS_URL || process.env.KV_URL || process.env.REDIS_CONNECTION_STRING;
const upstashUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const upstashToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

// 1. Initialize TCP ioredis if connection string (redis:// or rediss://) provided
if (redisConnString && (redisConnString.startsWith('redis://') || redisConnString.startsWith('rediss://'))) {
  try {
    ioRedisClient = new IoRedis(redisConnString, {
      maxRetriesPerRequest: 3,
      connectTimeout: 5000,
      lazyConnect: false,
    });
    ioRedisClient.on('connect', () => console.log('✅ TCP Redis Queue connected successfully'));
    ioRedisClient.on('error', (err) => console.warn('⚠️ TCP Redis connection error:', err.message));
  } catch (e: any) {
    console.warn('⚠️ Failed to initialize TCP ioredis:', e.message);
  }
}
// 2. Initialize Upstash REST client if REST URL & TOKEN provided
else if (upstashUrl && upstashToken) {
  try {
    upstashClient = new UpstashRedis({
      url: upstashUrl,
      token: upstashToken,
    });
    console.log('✅ Upstash REST Redis Queue initialized successfully');
  } catch (e: any) {
    console.warn('⚠️ Upstash REST Redis initialization warning:', e.message);
  }
} else {
  console.log('ℹ️ Operating in direct non-blocking mode (No Redis env vars configured)');
}

export interface EmailJob {
  id: string; // Firestore Document ID
  type: 'registration_and_credentials' | 'custom_email';
  email: string;
  name: string;
  regNo?: string;
  password?: string;
  subject?: string;
  messageHtml?: string;
  timestamp: string;
}

// Internal helper to process email job and update Firestore with REAL delivery status
export async function executeAndVerifyEmailJob(job: EmailJob): Promise<boolean> {
  let success = false;
  let errorMsg: string | null = null;

  try {
    // Attempt 1: Try direct Gmail REST API via Google OAuth (Fastest & Guaranteed Inbox Delivery)
    if (job.type === 'registration_and_credentials') {
      let res1 = false;
      let res2 = false;

      try {
        res1 = await sendRegistrationEmail(job.email, job.name);
        if (job.regNo && job.password) {
          res2 = await sendCandidateCredentialsEmail(job.email, job.name, job.regNo, job.password);
        } else {
          res2 = true;
        }
      } catch (e: any) {
        console.warn('⚠️ Gmail REST API primary dispatch attempt encountered error:', e.message || e);
      }

      if (res1 && res2) {
        success = true;
        console.log(`✅ [Email Service] Registration & Credentials emails delivered successfully to ${job.email} via Gmail API.`);
      } else {
        console.log('ℹ️ Gmail REST API primary attempt incomplete, falling back to SMTP Microservice...');
        let sendEmailAttachments = false
        let whatsappLink = 'https://chat.whatsapp.com/EYnVs0kP906FdQToxrYCsR'
        let syllabusFiles: Array<{ title: string; url: string }> = []
        let coordinators = [
          { name: 'Ashutosh Mehta', role: 'Coordinator', phone: '+919027042638' },
          { name: 'Anmol Ranjan', role: 'Coordinator & Treasurer', phone: '+916201957167' }
        ]

        if (db) {
          try {
            const settingsDoc = await db.collection('settings').doc('general').get()
            if (settingsDoc.exists) {
              const data = settingsDoc.data()
              if (data?.sendEmailAttachments !== undefined) sendEmailAttachments = data.sendEmailAttachments === true
              if (data?.whatsappLink) whatsappLink = data.whatsappLink
              if (Array.isArray(data?.syllabusFiles) && data.syllabusFiles.length > 0) syllabusFiles = data.syllabusFiles
              if (Array.isArray(data?.contactDetails) && data.contactDetails.length > 0) coordinators = data.contactDetails
            }
          } catch (e) {}
        }

        const msSuccess = await sendEmailViaMicroservice({
          email: job.email,
          name: job.name,
          regNo: job.regNo,
          password: job.password,
          sendEmailAttachments,
          whatsappLink,
          syllabusFiles,
          coordinators
        });

        if (msSuccess) {
          success = true;
        } else {
          success = false;
          errorMsg = 'Email dispatch failed on both primary Gmail API and fallback microservice.';
        }
      }
    } else if (job.type === 'custom_email' && job.subject && job.messageHtml) {
      success = await sendCustomEmail(job.email, job.subject, job.messageHtml);
      if (!success) {
        errorMsg = 'Custom email dispatch failed.';
      }
    }

  } catch (err: any) {
    success = false;
    errorMsg = err.message || 'Email delivery exception occurred';
    console.error(`Email dispatch error for job ${job.id}:`, err);
  }

  // Update Firestore database with verified email delivery status
  if (job.id && db) {
    try {
      await db.collection('registrations').doc(job.id).set(
        {
          emailSent: success,
          emailError: success ? null : errorMsg,
          lastEmailAttemptAt: new Date().toISOString()
        },
        { merge: true }
      );
    } catch (e) {
      console.error(`Failed to update Firestore status for doc ${job.id}:`, e);
    }
  }

  return success;
}

// Push job to Redis queue or execute background async job with verified DB status update
export async function pushEmailJob(job: EmailJob) {
  // Option 1: TCP IoRedis
  if (ioRedisClient && ioRedisClient.status === 'ready') {
    try {
      await ioRedisClient.lpush('endeavour_email_queue', JSON.stringify(job));
      // Process job immediately in background
      (async () => { await executeAndVerifyEmailJob(job); })();
      return { queued: true, provider: 'ioredis' };
    } catch (err: any) {
      console.error('Failed to push to TCP Redis:', err.message);
    }
  }

  // Option 2: Upstash REST Redis
  if (upstashClient) {
    try {
      await upstashClient.lpush('endeavour_email_queue', JSON.stringify(job));
      // Process job immediately in background
      (async () => { await executeAndVerifyEmailJob(job); })();
      return { queued: true, provider: 'upstash' };
    } catch (err: any) {
      console.error('Failed to push to Upstash REST Redis:', err.message);
    }
  }

  // Option 3: Direct async non-blocking execution fallback with verified status update
  (async () => {
    await executeAndVerifyEmailJob(job);
  })();

  return { queued: false, provider: 'fallback' };
}
