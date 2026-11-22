import { Link } from 'react-router-dom'
function Home() {
  return (
    <section className="background">
      <h1>Quizzy</h1>
      <p>What do you know about TAMUCC?</p>
      <Link className="button" to="/play">
        Start Game
      </Link>
    </section>
  )
}

export default Home