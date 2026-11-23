import { Link } from 'react-router-dom'

// Display a fallback page when the requested route does not exist.
function NotFound() {
  return (
    <section>
      <h1>Page not found</h1>
      <Link to="/">Return home</Link>
    </section>
  )
}

export default NotFound