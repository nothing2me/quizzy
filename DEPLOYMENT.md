# Vercel Deployment Guide

This guide will help you deploy the Quizzy application to Vercel through GitHub.

## Prerequisites

- GitHub account
- Vercel account (sign up at [vercel.com](https://vercel.com))
- Your code pushed to a GitHub repository

## Step 1: Push to GitHub

1. Initialize a git repository (if not already done):
```bash
git init
git add .
git commit -m "Initial commit"
```

2. Create a new repository on GitHub

3. Push your code:
```bash
git remote add origin <your-github-repo-url>
git branch -M main
git push -u origin main
```

## Step 2: Deploy to Vercel

### Option A: Via Vercel Dashboard

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click **"Add New Project"**
3. Import your GitHub repository
4. Vercel will automatically detect the Python configuration
5. Click **"Deploy"**

### Option B: Via Vercel CLI

1. Install Vercel CLI:
```bash
npm i -g vercel
```

2. Login to Vercel:
```bash
vercel login
```

3. Deploy:
```bash
vercel
```

4. Follow the prompts to complete deployment

## Step 3: Configure Environment Variables

1. Go to your project settings in Vercel
2. Navigate to **"Environment Variables"**
3. Add the following variables:

```
SECRET_KEY=<generate-a-secure-random-key>
DATABASE_URL=sqlite:///tmp/flashcards.db
DEBUG=False
```

**To generate a secure SECRET_KEY:**
```python
import secrets
print(secrets.token_urlsafe(32))
```

## Important Limitations on Vercel

### ⚠️ Database Storage

**SQLite on Vercel is ephemeral!** The `/tmp` directory is cleared between function invocations. This means:

- ❌ Data will NOT persist between deployments
- ❌ Data will NOT persist across function invocations
- ❌ Each user may get a fresh database on each request

### ✅ Recommended Solutions

For production use, migrate to one of these databases:

1. **Vercel Postgres** (Recommended)
   - Native Vercel integration
   - Free tier available
   - Easy setup

2. **Supabase** (Free tier)
   - PostgreSQL database
   - Free tier: 500MB storage
   - Easy to set up

3. **PlanetScale** (Free tier)
   - MySQL database
   - Serverless scaling
   - Free tier available

4. **Neon** (Free tier)
   - PostgreSQL database
   - Serverless Postgres
   - Free tier available

### Database Migration Steps

To migrate from SQLite to PostgreSQL:

1. **Update requirements.txt**:
```
psycopg2-binary==2.9.9
```

2. **Update main.py** database connection:
```python
import psycopg2
from psycopg2.extras import RealDictCursor
import os

def get_db_connection():
    if os.environ.get("DATABASE_URL"):
        # PostgreSQL connection
        conn = psycopg2.connect(
            os.environ.get("DATABASE_URL"),
            cursor_factory=RealDictCursor
        )
    else:
        # SQLite fallback for local dev
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
    return conn
```

3. **Update SQL queries** to be PostgreSQL compatible (SQLite and PostgreSQL are mostly compatible)

### ⚠️ Session Management

In-memory sessions won't work on Vercel because each function invocation is isolated. Consider:

1. **Database-backed sessions** - Store sessions in your database
2. **Redis** - Use Upstash Redis (free tier available)
3. **JWT tokens** - Stateless authentication

## Troubleshooting

### Build Fails

- Check that `requirements.txt` is in the root directory
- Verify all dependencies are listed
- Check Python version (should be 3.9+)

### Application Not Loading

- Check Vercel function logs in the dashboard
- Verify `api/index.py` exists and is correct
- Check that `vercel.json` is properly configured

### Templates Not Found

- Ensure `templates/` directory is in the root
- Check that templates are not in `.vercelignore`
- Verify `BASE_DIR` is correctly set

### Database Errors

- Remember: SQLite on Vercel is ephemeral
- Consider migrating to a persistent database
- Check database connection string

## Monitoring

- View logs in Vercel Dashboard → Your Project → Functions
- Set up error tracking with Sentry (optional)
- Monitor function execution times

## Custom Domain

1. Go to Project Settings → Domains
2. Add your custom domain
3. Follow DNS configuration instructions

## Next Steps

1. ✅ Set up a persistent database (PostgreSQL recommended)
2. ✅ Implement database-backed sessions
3. ✅ Configure custom domain
4. ✅ Set up monitoring and error tracking
5. ✅ Enable HTTPS (automatic on Vercel)

## Support

For Vercel-specific issues:
- [Vercel Documentation](https://vercel.com/docs)
- [Vercel Community](https://github.com/vercel/vercel/discussions)

For application issues:
- Open an issue on GitHub

