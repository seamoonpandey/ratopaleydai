# Environment Variables Configuration

## Core API (Backend)

Create a `.env` file in the `core/` directory:

```bash
# Database
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel
# OR individual DB settings:
DB_HOST=localhost
DB_PORT=5432
DB_USER=rs
DB_PASS=rs
DB_NAME=redsentinel

# Redis (for queue)
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT Authentication
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/callback/google

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:3000/auth/callback/github

# Frontend URL (for OAuth redirects)
FRONTEND_URL=http://localhost:3001

# API Key (optional, for backwards compatibility)
API_KEY_SECRET=your-api-key-for-direct-access

# CORS
CORS_ORIGIN=http://localhost:3001

# Server
PORT=3000
NODE_ENV=development
```

## Dashboard (Frontend)

Create a `.env.local` file in the `dashboard/` directory:

```bash
# Core API URL
NEXT_PUBLIC_CORE_API_URL=http://localhost:3000

# OAuth Credentials (must match backend)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# NextAuth
NEXTAUTH_URL=http://localhost:3001
NEXTAUTH_SECRET=your-nextauth-secret-key
```

## Setting Up OAuth Providers

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Set application type to "Web application"
6. Add authorized redirect URIs:
   - `http://localhost:3000/auth/callback/google` (for backend)
   - `http://localhost:3001/api/auth/callback/google` (for NextAuth)
7. Copy Client ID and Client Secret to your `.env` files

### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in:
   - Application name: `RedSentinel` (or your choice)
   - Homepage URL: `http://localhost:3001`
   - Authorization callback URL: `http://localhost:3000/auth/callback/github`
4. Click "Register application"
5. Copy Client ID and generate a Client Secret
6. Add them to your `.env` files

## Production Deployment

For production, update the following:

1. **JWT_SECRET**: Generate a strong random secret
   ```bash
   openssl rand -base64 32
   ```

2. **NEXTAUTH_SECRET**: Generate another strong secret
   ```bash
   openssl rand -base64 32
   ```

3. **URLs**: Update all URLs to use your production domain:
   - GOOGLE_CALLBACK_URL
   - GITHUB_CALLBACK_URL
   - FRONTEND_URL
   - NEXT_PUBLIC_CORE_API_URL
   - NEXTAUTH_URL

4. **OAuth Credentials**: Create separate OAuth apps for production with production callback URLs

5. **CORS_ORIGIN**: Set to your frontend domain (no wildcard in production)

6. **NODE_ENV**: Set to `production`

## Security Notes

- Never commit `.env` files to version control
- Use different OAuth credentials for development and production
- Rotate secrets regularly
- Keep JWT_SECRET and NEXTAUTH_SECRET secure and unique
- In production, use environment variables from your hosting platform
