import React, { createContext, useContext, useState, useEffect } from 'react'
import { auth } from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true

    const loadUser = async () => {
      try {
        const res = await auth.me()
        if (!active) return
        const userData = res.data
        setUser(userData)
        localStorage.setItem('user', JSON.stringify(userData))
        localStorage.setItem('user_id', userData.id)
      } catch {
        if (!active) return
        setUser(null)
        localStorage.removeItem('user')
        localStorage.removeItem('token')
        localStorage.removeItem('user_id')
      } finally {
        if (active) setLoading(false)
      }
    }

    loadUser()

    return () => {
      active = false
    }
  }, [])

  const login = async (username, password) => {
    const res = await auth.login({ username, password })
    const { user: userData, token } = res.data
    setUser(userData)
    localStorage.setItem('user', JSON.stringify(userData))
    localStorage.setItem('token', token)
    localStorage.setItem('user_id', userData.id)
    return userData
  }

  const register = async (data) => {
    const res = await auth.register(data)
    const userData = res.data.user
    setUser(userData)
    localStorage.setItem('user', JSON.stringify(userData))
    localStorage.setItem('user_id', userData.id)
    return userData
  }

  const logout = async () => {
    await auth.logout().catch(() => {})
    setUser(null)
    localStorage.removeItem('user')
    localStorage.removeItem('token')
    localStorage.removeItem('user_id')
  }

  const isAdmin = user?.role === 'admin'

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, isAdmin }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
