# Endeavour SLIET - Cloudflare Worker Backend

This directory contains the Cloudflare Worker compatible version of the Endeavour SLIET backend built with Hono and TypeScript.

## Quick Start (Local Development)

To run the worker locally using `wrangler`:

```bash
cd backend/worker
npm install
npx wrangler dev
```

The worker API will run locally on `http://localhost:8787`.

## Deploying to Cloudflare Workers

To deploy the worker directly to your Cloudflare account:

```bash
cd backend/worker
npx wrangler deploy
```

## Environment Variables / Secrets

Secret variables can be set via Wrangler:

```bash
npx wrangler secret put FIREBASE_PRIVATE_KEY
npx wrangler secret put GOOGLE_CLIENT_SECRET
```
