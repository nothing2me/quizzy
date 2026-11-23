import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.jsx'

// Mount the React application inside the root element in index.html.
createRoot(document.getElementById('root')).render(
  <StrictMode>
    {/* Enable client-side routing throughout the application. */}
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)