import React, { useState, useEffect } from 'react'
import { admin, products } from '../api/client'

export default function Admin() {
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [command, setCommand] = useState('echo CloudCart Admin Panel')
  const [output, setOutput] = useState('')
  const [newProduct, setNewProduct] = useState({ name: '', price: 0, category: '', description: '' })

  useEffect(() => {
    admin.stats().then((res) => setStats(res.data)).catch(() => {})
    admin.users().then((res) => setUsers(res.data)).catch(() => {})
  }, [])

  const handleExec = async () => {
    try {
      const res = await admin.exec(command)
      setOutput(res.data.output)
    } catch (err) {
      setOutput(err.response?.data?.error || 'Command failed')
    }
  }

  const handleCreateProduct = async (e) => {
    e.preventDefault()
    if (!newProduct.name.trim() || Number(newProduct.price) <= 0) return
    await products.create(newProduct)
    setNewProduct({ name: '', price: 0, category: '', description: '' })
    admin.stats().then((res) => setStats(res.data))
  }

  return (
    <div className="container" style={{ padding: '2rem 1rem' }}>
      <h1>Admin Dashboard</h1>
      <p style={{ color: 'var(--danger)', fontSize: '0.875rem' }}>
        VULN: No authorization check on admin routes
      </p>

      {stats && (
        <div className="grid grid-3" style={{ marginBottom: '2rem' }}>
          <div className="card"><h3>{stats.users}</h3><p>Users</p></div>
          <div className="card"><h3>{stats.products}</h3><p>Products</p></div>
          <div className="card"><h3>${stats.revenue?.toFixed(2)}</h3><p>Revenue</p></div>
        </div>
      )}

      <div className="card" style={{ marginBottom: '1rem' }}>
        <h3>Add Product</h3>
        <form onSubmit={handleCreateProduct}>
          <div className="form-group">
            <input placeholder="Name" value={newProduct.name} onChange={(e) => setNewProduct({ ...newProduct, name: e.target.value })} />
          </div>
          <div className="form-group">
            <input type="number" placeholder="Price" value={newProduct.price} onChange={(e) => setNewProduct({ ...newProduct, price: parseFloat(e.target.value) })} />
          </div>
          <button type="submit" className="btn btn-primary">Create Product</button>
        </form>
      </div>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <h3>Command Console (VULN: Command Injection)</h3>
        <div className="form-group">
          <input value={command} onChange={(e) => setCommand(e.target.value)} />
        </div>
        <button className="btn btn-danger" onClick={handleExec}>Execute</button>
        {output && <pre style={{ marginTop: '1rem', background: '#1e293b', color: '#e2e8f0', padding: '1rem', borderRadius: 6, overflow: 'auto' }}>{output}</pre>}
      </div>

      <div className="card">
        <h3>All Users (Sensitive Data Exposed)</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              <th style={{ textAlign: 'left', padding: '0.5rem' }}>ID</th>
              <th>Username</th>
              <th>Role</th>
              <th>API Key</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '0.5rem' }}>{u.id}</td>
                <td>{u.username}</td>
                <td><span className={`badge badge-${u.role}`}>{u.role}</span></td>
                <td style={{ fontSize: '0.7rem' }}>{u.api_key?.substring(0, 20)}...</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
