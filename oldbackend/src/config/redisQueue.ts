import { Redis as UpstashRedis } from '@upstash/redis';
import IoRedis from 'ioredis';
import { sendRegistrationEmail, sendCandidateCredentialsEmail, sendCustomEmail } from './mail.js';
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
    if (job.type === 'registration_and_credentials') {
      const res1 = await sendRegistrationEmail(job.email, job.name);
      let res2 = true;
      if (job.regNo && job.password) {
        res2 = await sendCandidateCredentialsEmail(job.email, job.name, job.regNo, job.password);
      }
      if (res1 && res2) {
        success = true;
      } else {
        success = false;
        errorMsg = 'SMTP dispatch failed. Please check server email log.';
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
