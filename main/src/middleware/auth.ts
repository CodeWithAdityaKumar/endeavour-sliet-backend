import { MiddlewareHandler } from 'hono'
import { verify } from 'hono/jwt'
import dotenv from 'dotenv'

dotenv.config()

export const adminAuthMiddleware = (): MiddlewareHandler => {
  return async (c, next) => {
    const authHeader = c.req.header('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized: Missing or invalid token format' }, 401)
    }

    const token = authHeader.split(' ')[1]
    const jwtSecret = process.env.JWT_SECRET || 'endeavour_secret_key_2025'
    try {
      const decoded: any = await verify(token, jwtSecret, 'HS256')
      
      // Strict Role Validation: Ensure candidate tokens cannot access admin APIs
      if (!decoded || (decoded.role !== 'admin' && decoded.role !== 'superadmin')) {
        return c.json({ error: 'Forbidden: Admin privilege required' }, 403)
      }

      // Store payload in context variables
      c.set('jwtPayload', decoded)
      await next()
    } catch (err) {
      return c.json({ error: 'Unauthorized: Invalid or expired token' }, 401)
    }
  }
}

export const superAdminAuthMiddleware = (): MiddlewareHandler => {
  return async (c, next) => {
    const authHeader = c.req.header('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized: Missing or invalid token format' }, 401)
    }

    const token = authHeader.split(' ')[1]
    const jwtSecret = process.env.JWT_SECRET || 'endeavour_secret_key_2025'
    try {
      const decoded: any = await verify(token, jwtSecret, 'HS256')
      
      if (!decoded || decoded.role !== 'superadmin') {
        return c.json({ error: 'Forbidden: Only Super Admin can perform this action' }, 403)
      }

      c.set('jwtPayload', decoded)
      await next()
    } catch (err) {
      return c.json({ error: 'Unauthorized: Invalid or expired token' }, 401)
    }
  }
}
