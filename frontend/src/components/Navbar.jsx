import React from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import './Navbar.css'

export default function Navbar() {
  const { user, logout, isAdmin } = useAuth()
  const navigate = useNavigate()
  const initials = user?.username?.slice(0, 2).toUpperCase()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <nav className="navbar">
      <div className="container navbar-inner">
        <Link to="/" className="navbar-brand">
          <img src="/cloudcart.svg" alt="CloudCart" width="32" height="32" />
          CloudCart
        </Link>

        <div className="navbar-links">
          <NavLink to="/products">Products</NavLink>
          {user && <NavLink to="/cart">Cart</NavLink>}
          {user && <NavLink to="/orders">Orders</NavLink>}
          {isAdmin && <NavLink to="/admin">Admin</NavLink>}
          {user ? (
            <>
              <NavLink to="/profile" className="account-chip" aria-label={`Profile for ${user.username}`}>
                <span className="account-avatar">{initials}</span>
              </NavLink>
              <button type="button" className="btn btn-outline" onClick={handleLogout}>Logout</button>
            </>
          ) : (
            <>
              <NavLink to="/login">Login</NavLink>
              <Link to="/register" className="btn btn-primary">Register</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  )
}
