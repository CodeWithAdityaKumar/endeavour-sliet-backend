import { v2 as cloudinary } from 'cloudinary'
import dotenv from 'dotenv'
import crypto from 'crypto'

dotenv.config()

const cloudName = process.env.CLOUDINARY_CLOUD_NAME
const apiKey = process.env.CLOUDINARY_API_KEY
const apiSecret = process.env.CLOUDINARY_API_SECRET

let isCloudinaryConfigured = false

if (cloudName && apiKey && apiSecret) {
  cloudinary.config({
    cloud_name: cloudName,
    api_key: apiKey,
    api_secret: apiSecret,
  })
  isCloudinaryConfigured = true
  console.log('Cloudinary configured successfully.')
} else {
  console.warn('Cloudinary credentials missing. Cloudinary integration disabled.')
}

export const uploadToCloudinary = async (
  file: File | Blob,
  folder: string,
  resourceType: 'image' | 'raw' | 'auto' = 'auto'
): Promise<string> => {
  if (!isCloudinaryConfigured) {
    throw new Error('Cloudinary is not configured on the backend.')
  }

  const MAX_SIZE = 5 * 1024 * 1024 // 5 MB limit
  if (file.size > MAX_SIZE) {
    throw new Error(`File size is too large (${(file.size / (1024 * 1024)).toFixed(2)} MB). Maximum allowed size is 5 MB.`)
  }

  const arrayBuffer = await file.arrayBuffer()
  const buffer = Buffer.from(arrayBuffer)

  // Parse original filename to extract extension
  const originalName = (file as File).name || 'file'
  const fileExtension = originalName.includes('.') 
    ? originalName.substring(originalName.lastIndexOf('.')) 
    : ''
  
  // Generate random unique filename
  const uniqueId = crypto.randomBytes(8).toString('hex')

  // Cloudinary requirement: raw files must have their file extension in the public_id.
  // Image assets must omit the extension to avoid double extensions.
  const publicId = resourceType === 'raw' 
    ? `${uniqueId}${fileExtension}`
    : uniqueId

  const attemptUpload = (attempt: number): Promise<string> => {
    return new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        { 
          folder, 
          resource_type: resourceType,
          public_id: publicId
        },
        async (error, result) => {
          if (error) {
            if (attempt < 2) {
              console.warn(`Cloudinary upload failed (attempt ${attempt + 1}), retrying in 1s...`, error.message || error)
              await new Promise(r => setTimeout(r, 1000))
              try {
                const retryUrl = await attemptUpload(attempt + 1)
                resolve(retryUrl)
              } catch (retryErr) {
                reject(retryErr)
              }
            } else {
              reject(error)
            }
          } else if (result && result.secure_url) {
            resolve(result.secure_url)
          } else {
            reject(new Error('Cloudinary upload returned empty response'))
          }
        }
      ).end(buffer)
    })
  }

  return attemptUpload(0)
}

