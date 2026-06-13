import React, { useState, useEffect } from 'react'
import { profile } from '../api/client'
import { useAuth } from '../context/AuthContext'
import { vuln } from '../api/client'

export default function Profile() {
  const { user } = useAuth()
  const [form, setForm] = useState({ full_name: '', email: '' })
  const [apiKey, setApiKey] = useState('')
  const [uploadFile, setUploadFile] = useState(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (user) {
      profile.get(user.id).then((res) => {
        setForm({ full_name: res.data.full_name || '', email: res.data.email || '' })
      })
      profile.get(user.id).then(() => {
        fetch(`/api/profile/${user.id}/api-key`)
          .then((r) => r.json())
          .then((d) => setApiKey(d.api_key || ''))
          .catch(() => {})
      })
    }
  }, [user])

  const handleUpdate = async (e) => {
    e.preventDefault()
    await profile.update(user.id, form)
    setMessage('Profile updated!')
  }

  const handleUpload = async (e) => {
    e.preventDefault()
    if (!uploadFile) return
    const fd = new FormData()
    fd.append('file', uploadFile)
    await vuln.upload(fd)
    setMessage('File uploaded!')
  }

  if (!user) return <div className="container">Please login.</div>

  return (
    <div className="container" style={{ padding: '2rem 1rem', maxWidth: 600 }}>
      <h1>My Profile</h1>
      {message && <div className="alert alert-success">{message}</div>}

      <div className="card" style={{ marginBottom: '1rem' }}>
        <p>Username: <strong>{user.username}</strong></p>
        <p>Role: <span className={`badge badge-${user.role}`}>{user.role}</span></p>
        {apiKey && <p style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>API Key: {apiKey}</p>}
      </div>

      <form onSubmit={handleUpdate} className="card" style={{ marginBottom: '1rem' }}>
        <h3>Edit Profile</h3>
        <div className="form-group">
          <label>Full Name</label>
          <input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
        </div>
        <div className="form-group">
          <label>Email</label>
          <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </div>
        <button type="submit" className="btn btn-primary">Save</button>
      </form>

      <form onSubmit={handleUpload} className="card">
        <h3>Upload Avatar</h3>
        <div className="form-group">
          <input type="file" onChange={(e) => setUploadFile(e.target.files[0])} />
        </div>
        <button type="submit" className="btn btn-outline">Upload</button>
      </form>
    </div>
  )
}
