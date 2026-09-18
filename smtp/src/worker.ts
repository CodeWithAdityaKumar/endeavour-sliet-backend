import app from './index.js'

export default {
  fetch(request: Request, env: any, ctx: any) {
    return app.fetch(request, env, ctx)
  }
}
