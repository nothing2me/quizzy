# Quizzy

Quizzy is a trivia game focused on Texas A&M University–Corpus Christi (TAMU–CC) and the surrounding Corpus Christi area.

## Current Features

- React frontend with client-side routing and persistent navigation.
- Timed multiple-choice trivia questions.
- PostgreSQL database for storing questions and answer choices.
- Express REST API for retrieving questions and validating answers.
- Answer feedback, score tracking, and quiz results.

## Technologies

- **Frontend:** React, Vite, React Router
- **Backend:** Node.js, Express
- **Database:** PostgreSQL

## Running Locally

### Prerequisites

- Node.js (20.19+ or 22.12+)
- PostgreSQL

### Setup

1. Clone the repository and open the project folder in VS Code.
2. Install dependencies:

   `npm install`

3. Create a PostgreSQL database named `quizzy_dev`.
4. Run `server/sql/schema.sql` followed by `server/sql/seed.sql` in the `quizzy_dev` database.
5. Create a `.env` file in the project root containing:

   `DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/quizzy_dev`

   Replace `YOUR_PASSWORD` with your own local PostgreSQL password. Do not commit your `.env` file.

6. Start the Express API:

   `npm run api`

7. In a second terminal, start the React frontend:

   `npm run dev`

8. Open the local URL provided by Vite.

To verify the backend and database connection, visit `http://localhost:3001/api/health`.

## Planned Features

- User registration, login, and authentication.
- Persistent user scores and quiz history.
- Leaderboards and player statistics.
- Additional question sets and difficulty levels.
- Potential turn-based boss battle mechanics.

## Team Members

- Noah Wilborn
- Andrew Tamez
- Bryce Spicer
- Jacob Zimmerhanzel