# Quizzy - Collaborative Flashcard Application

A production-ready collaborative flashcard web application built with FastAPI, featuring Quizlet import, multiple study modes, and comprehensive security features.

## Features

- 🔐 **Secure Authentication** - Password hashing, rate limiting, account lockout
- 📚 **Flashcard Management** - Create, edit, and manage flashcard sets
- 👥 **Collaboration** - Share sets and collaborate with other users
- 📥 **Quizlet Import** - Import flashcard sets from Quizlet
- 🎓 **Multiple Study Modes** - Flashcard, Test, and Learn modes
- 🧮 **LaTeX Support** - Math equations rendered with KaTeX
- 👨‍💼 **Admin Panel** - User management and security monitoring

## Technology Stack

- **Backend**: FastAPI (Python)
- **Database**: SQLite (can be migrated to PostgreSQL for production)
- **Templates**: Jinja2
- **Frontend**: Bootstrap 5, Font Awesome
- **Security**: bcrypt, passlib, slowapi

## Local Development

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd open-quizzes-main
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables (optional):
```bash
cp env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
python migrate_database.py
```

6. Run the application:
```bash
python main.py
```

The application will be available at `http://localhost:8000`

## Vercel Deployment

This application is configured for deployment on Vercel through GitHub.

### Prerequisites

- GitHub account
- Vercel account (free tier works)
- Repository pushed to GitHub

### Deployment Steps

1. **Push to GitHub**:
   - Push your code to a GitHub repository

2. **Connect to Vercel**:
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "Add New Project"
   - Import your GitHub repository
   - Vercel will automatically detect the Python configuration

3. **Configure Environment Variables** (optional):
   - In Vercel project settings, add environment variables from `env.example`
   - Set `SECRET_KEY` to a secure random value

4. **Deploy**:
   - Vercel will automatically build and deploy
   - The first deployment may take a few minutes

### Important Notes for Vercel

⚠️ **Database Limitations**: 
- SQLite files are stored in `/tmp` on Vercel, which is ephemeral
- Data will be lost on each function invocation
- **For production**, consider migrating to:
  - **Vercel Postgres** (recommended)
  - **Supabase** (free tier available)
  - **PlanetScale** (MySQL)
  - **Neon** (PostgreSQL)

To use an external database:
1. Update `DATABASE_PATH` in `main.py` to use environment variable
2. Use a database connection library (e.g., `psycopg2` for PostgreSQL)
3. Update connection logic in `get_db_connection()`

### Vercel Project Structure

```
open-quizzes-main/
├── api/
│   └── index.py          # Vercel serverless function handler
├── vercel.json           # Vercel configuration
├── .vercelignore         # Files to ignore in deployment
├── requirements.txt      # Python dependencies
└── main.py              # FastAPI application
```

## Project Structure

```
open-quizzes-main/
├── api/
│   └── index.py          # Vercel handler
├── templates/            # Jinja2 HTML templates
│   ├── admin/           # Admin panel templates
│   └── *.html          # Application templates
├── main.py              # Main FastAPI application
├── security.py          # Security module
├── quizlet_importer.py  # Quizlet import functionality
├── migrate_database.py  # Database migration script
├── requirements.txt     # Python dependencies
├── vercel.json         # Vercel configuration
└── env.example          # Environment variables template
```

## Environment Variables

Create a `.env` file (or set in Vercel) with:

```env
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=sqlite:///flashcards.db
DEBUG=False
```

## Database Migration

The application includes a migration script to upgrade existing databases:

```bash
python migrate_database.py
```

This will:
- Create a backup of your database
- Add new security columns
- Create indexes for performance
- Set up security logging

## Security Features

- ✅ Password hashing with bcrypt (12 rounds)
- ✅ Rate limiting (5 attempts/minute for login)
- ✅ Account lockout (15 minutes after 5 failed attempts)
- ✅ Input validation and sanitization
- ✅ Security headers (CSP, X-Frame-Options, etc.)
- ✅ CSRF protection
- ✅ Security event logging

## Study Modes

1. **Flashcard Mode** - Flip through cards (ordered or random)
2. **Test Mode** - Multiple choice questions
3. **Learn Mode** - Multiple choice without authentication

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

[Add your license here]

## Support

For issues and questions, please open an issue on GitHub.

