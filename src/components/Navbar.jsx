import { NavLink } from 'react-router-dom'

// Provide persistent navigation between the application's pages.
function Navbar() {
  return (
    <header>
      {/* Link the application brand to the homepage. */}
      <NavLink className="brand" to="/" end>
        Quizzy
      </NavLink>

      {/* Use client-side navigation without reloading the application. */}
      <nav aria-label="Main navigation">
        <NavLink to="/" end>
          Home
        </NavLink>
        <NavLink to="/about">About</NavLink>
      </nav>
    </header>
  )
}

export default Navbar