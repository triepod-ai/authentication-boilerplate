import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from '../context/AuthContext'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider apiUrl="http://localhost:5000/api/auth">
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
