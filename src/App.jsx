import { Route, Routes } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import About from './pages/About.jsx'
import Home from './pages/Home.jsx'
import Play from './pages/Play.jsx'
import NotFound from './pages/NotFound.jsx'
import './App.css'

// Define the shared application layout and client-side page routes.
function App() {
  return (
    <>
      {/* Keep navigation visible while the active page changes. */}
      <Navbar />

      <main className="page">
        {/* Render the matching page without a full browser reload. */}
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/play" element={<Play />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </>
  )
}

export default App