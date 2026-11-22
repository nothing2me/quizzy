import { NavLink } from 'react-router-dom'

function Navbar() {
  return (
    <header>
      <NavLink className="brand" to="/" end>
        Quizzy
      </NavLink>
      <nav aria-label="Main navigation">
        <NavLink to="/" end>
          Home
        </NavLink>
        <NavLink to="/about">About</NavLink>
        <NavLink to="/profile">Profile</NavLink>
        <NavLink to="/leaderboard">Leaderboard</NavLink>
      </nav>
    </header>
  )
}

export default Navbar
