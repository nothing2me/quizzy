import { Link } from 'react-router-dom'

// Display the landing page and provide an entry point to the quiz.
function Home() {
  return (
    <section className="background">
      <h1>Quizzy</h1>
      <p>What do you know about TAMUCC?</p>

      {/* Navigate to the gameplay page without a full browser reload. */}
      <Link className="button" to="/play">
        Start Game
      </Link>
    </section>
  )
}

export default Home