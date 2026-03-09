# OAuth Setup Guide

This guide explains how to set up Google and GitHub OAuth authentication for RedSentinel.

## Architecture Overview

RedSentinel uses a **backend-first OAuth flow**:
1. Frontend redirects to backend OAuth endpoints (`/auth/google` or `/auth/github`)
2. Backend handles OAuth with providers using Passport.js
3. Backend creates/updates user in database
4. Backend generates JWT token
5. Backend redirects to frontend with JWT token
6. Frontend stores JWT and uses it for all API requests

## Prerequisites

- Google Cloud Console account (for Google OAuth)
- GitHub account (for GitHub OAuth)
- Backend running on a publicly accessible URL (for production) or localhost (for development)

---

## 1. Google OAuth Setup

### Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Navigate to **APIs & Services** → **Credentials**

### Step 2: Create OAuth 2.0 Client

1. Click **Create Credentials** → **OAuth client ID**
2. Select **Application type**: Web application
3. Configure:
   - **Name**: RedSentinel
   - **Authorized JavaScript origins**:
     - Development: `http://localhost:3000`
     - Production: `https://your-backend-domain.com`
   - **Authorized redirect URIs**:
     - Development: `http://localhost:3000/auth/callback/google`
     - Production: `https://your-backend-domain.com/auth/callback/google`
4. Click **Create**
5. Copy the **Client ID** and **Client Secret**

### Step 3: Configure Backend

Add to `/workspaces/ratopaleydai/core/.env`:

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret-here
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/callback/google

# Frontend URL (where to redirect after OAuth)
FRONTEND_URL=http://localhost:3001
```

---

## 2. GitHub OAuth Setup

### Step 1: Create GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Configure:
   - **Application name**: RedSentinel
   - **Homepage URL**:
     - Development: `http://localhost:3001`
     - Production: `https://your-frontend-domain.com`
   - **Authorization callback URL**:
     - Development: `http://localhost:3000/auth/callback/github`
     - Production: `https://your-backend-domain.com/auth/callback/github`
4. Click **Register application**
5. Copy the **Client ID**
6. Click **Generate a new client secret** and copy it

### Step 2: Configure Backend

Add to `/workspaces/ratopaleydai/core/.env`:

```bash
# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id-here
GITHUB_CLIENT_SECRET=your-github-client-secret-here
GITHUB_CALLBACK_URL=http://localhost:3000/auth/callback/github

# Frontend URL (where to redirect after OAuth)
FRONTEND_URL=http://localhost:3001
```

---

## 3. Backend Configuration

### Complete `.env` File

Create `/workspaces/ratopaleydai/core/.env` with all required variables:

```bash
# ── server ──────────────────────────────────────────────────────
NODE_ENV=development
PORT=3000
CORS_ORIGIN=http://localhost:3001

# ── python microservices ─────────────────────────────────────────
CONTEXT_URL=http://context:5001
PAYLOAD_GEN_URL=http://payload-gen:5002
FUZZER_URL=http://fuzzer:5003

# ── redis ────────────────────────────────────────────────────────
REDIS_HOST=redis
REDIS_PORT=6379

# ── database ─────────────────────────────────────────────────────
DATABASE_URL=postgresql://rs:rs@postgres:5432/redsentinel

# ── JWT & API Key ────────────────────────────────────────────────
JWT_SECRET=your-super-secret-jwt-key-change-in-production
API_KEY_SECRET=your-legacy-api-key-for-backwards-compatibility

# ── Google OAuth ─────────────────────────────────────────────────
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/callback/google

# ── GitHub OAuth ─────────────────────────────────────────────────
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:3000/auth/callback/github

# ── Frontend URL ─────────────────────────────────────────────────
FRONTEND_URL=http://localhost:3001

# ── scan defaults ────────────────────────────────────────────────
DEFAULT_SCAN_DEPTH=3
DEFAULT_MAX_PAYLOADS=50
DEFAULT_TIMEOUT_MS=60000

# ── http client ──────────────────────────────────────────────────
HTTP_TIMEOUT=30000
```

### Run Database Migration

The User entity migration runs automatically on startup, but you can also run it manually:

```bash
cd core
npm run migration:run
```

---

## 4. Frontend Configuration

### Environment Variables

Create `/workspaces/ratopaleydai/dashboard/.env.local`:

```bash
# Core API URL (backend)
NEXT_PUBLIC_CORE_API_URL=http://localhost:3000
```

**Note**: The frontend doesn't need OAuth credentials since the backend handles all OAuth logic.

---

## 5. Testing the OAuth Flow

### Start the Application

```bash
# Terminal 1: Start backend
cd /workspaces/ratopaleydai/core
npm run start:dev

# Terminal 2: Start frontend
cd /workspaces/ratopaleydai/dashboard
npm run dev
```

### Test Authentication

1. Open browser: `http://localhost:3001`
2. You should be redirected to `/auth/signin`
3. Click **Continue with Google** or **Continue with GitHub**
4. Complete OAuth flow with provider
5. You'll be redirected back to dashboard
6. User menu should show your name/email in top right

### Verify User Creation

Check the database:

```bash
docker exec -it postgres psql -U rs -d redsentinel -c "SELECT id, email, name, provider FROM users;"
```

---

## 6. API Authentication Methods

RedSentinel supports **two authentication methods**:

### Option 1: JWT Token (Recommended for web apps)

```bash
# Get token after OAuth login (stored in localStorage)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:3000/auth/me
```

### Option 2: User API Key (For programmatic access)

```bash
# Generate your API key in the dashboard (User Menu → Get API Key)
curl -H "x-api-key: YOUR_API_KEY" \
  http://localhost:3000/scans
```

### Generating an API Key

1. Sign in to dashboard
2. Click user menu (top right)
3. Click **Get API Key**
4. Copy and save the key securely

---

## 7. Production Deployment

### Update OAuth Redirect URLs

1. **Google Cloud Console**:
   - Add production backend URL to authorized origins
   - Add production callback URL: `https://api.yourdomain.com/auth/callback/google`

2. **GitHub OAuth App**:
   - Update homepage URL to production frontend
   - Update callback URL: `https://api.yourdomain.com/auth/callback/github`

### Update Environment Variables

Production `.env`:

```bash
NODE_ENV=production
CORS_ORIGIN=https://yourdomain.com

# Use strong secrets!
JWT_SECRET=generate-a-long-random-string-here
API_KEY_SECRET=another-strong-secret-key

# Production OAuth URLs
GOOGLE_CALLBACK_URL=https://api.yourdomain.com/auth/callback/google
GITHUB_CALLBACK_URL=https://api.yourdomain.com/auth/callback/github
FRONTEND_URL=https://yourdomain.com
```

---

## 8. Troubleshooting

### "Google OAuth credentials not configured"

- Check that `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set in backend `.env`
- Restart the backend after changing environment variables

### "Redirect URI mismatch" error

- Ensure the callback URL in your OAuth app settings **exactly matches** the `CALLBACK_URL` in your `.env`
- Check for trailing slashes and http vs https

### "Invalid or missing authentication"

- Check that JWT token is being sent in `Authorization: Bearer TOKEN` header
- Token expires after 7 days by default
- Generate a new API key if using key-based auth

### CORS errors

- Update `CORS_ORIGIN` in backend `.env` to match your frontend URL
- Restart backend after changes

### User not found after OAuth

- Check database connection
- Verify migration ran successfully: `npm run migration:show`
- Check backend logs for errors during OAuth flow

---

## Security Best Practices

1. **Never commit `.env` files** - They're already in `.gitignore`
2. **Use strong secrets** - Generate with `openssl rand -base64 32`
3. **Enable HTTPS in production** - Required for OAuth to work securely
4. **Rotate secrets regularly** - Especially if compromised
5. **Limit OAuth scopes** - Only request necessary permissions
6. **Validate redirect URIs** - Use exact URLs, not wildcards

---

## API Endpoints

### Public Endpoints
- `GET /health` - Health check (no auth required)

### OAuth Endpoints
- `GET /auth/google` - Initiate Google OAuth
- `GET /auth/github` - Initiate GitHub OAuth
- `GET /auth/callback/google` - Google OAuth callback
- `GET /auth/callback/github` - GitHub OAuth callback

### Protected Endpoints (Require JWT or API Key)
- `GET /auth/me` - Get current user profile
- `GET /auth/api-key` - Generate/retrieve user API key
- `POST /scan` - Create new scan
- `GET /scans` - List scans
- `GET /scan/:id` - Get scan details
- And all other scan/report endpoints...

---

## Next Steps

- ✅ OAuth is fully configured and working
- 💡 Consider adding email verification for additional security
- 💡 Implement role-based access control (RBAC) if needed
- 💡 Add rate limiting per user (currently global)
- 💡 Add OAuth scope management for different permission levels
