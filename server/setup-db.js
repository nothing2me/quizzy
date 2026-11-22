import 'dotenv/config'
import { readFile } from 'node:fs/promises'
import { pool } from './db.js'

try {
  for (const file of ['schema.sql', 'seed.sql']) {
    const path = new URL(`./sql/${file}`, import.meta.url)
    await pool.query(await readFile(path, 'utf8'))
    console.log(`Applied ${file}`)
  }
} finally {
  await pool.end()
}