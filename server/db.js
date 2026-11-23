import 'dotenv/config'
import pg from 'pg'

const { Pool } = pg

// Require a database connection string before initializing the pool.
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is missing. Add it to the project root .env file.')
}

// Share a PostgreSQL connection pool across the application's API endpoints.
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
})