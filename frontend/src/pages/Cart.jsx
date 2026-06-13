import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { cart, orders } from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function Cart() {
  const [items, setItems] = useState([])
  const [address, setAddress] = useState('')
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const { user } = useAuth()
  const navigate = useNavigate()

  const loadCart = () => {
    cart.get().then((res) => {
      setItems(res.data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }

  useEffect(() => { if (user) loadCart() }, [user])

  const total = items.reduce((sum, item) => {
    return sum + (item.product?.price || 0) * item.quantity
  }, 0)

  const handleRemove = async (itemId) => {
    await cart.remove(itemId)
    loadCart()
  }

  const handleCheckout = async () => {
    try {
      const res = await orders.checkout({ shipping_address: address })
      setMessage(`Order #${res.data.id} placed successfully!`)
      setTimeout(() => navigate('/orders'), 2000)
    } catch (err) {
      setMessage(err.response?.data?.error || 'Checkout failed')
    }
  }

  if (!user) return <div className="container">Please <a href="/login">login</a> to view your cart.</div>
  if (loading) return <div className="container">Loading cart...</div>

  return (
    <div className="container" style={{ padding: '2rem 1rem' }}>
      <h1>Shopping Cart</h1>
      {message && <div className="alert alert-success">{message}</div>}

      {items.length === 0 ? (
        <p>Your cart is empty. <a href="/products">Browse products</a></p>
      ) : (
        <>
          {items.map((item) => (
            <div key={item.id} className="card" style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3>{item.product?.name}</h3>
                <p>Qty: {item.quantity} × ${item.product?.price?.toFixed(2)}</p>
              </div>
              <button className="btn btn-danger" onClick={() => handleRemove(item.id)}>Remove</button>
            </div>
          ))}
          <div className="card">
            <h2>Total: ${total.toFixed(2)}</h2>
            <div className="form-group">
              <label>Shipping Address</label>
              <textarea value={address} onChange={(e) => setAddress(e.target.value)} rows={2} />
            </div>
            <button className="btn btn-primary" onClick={handleCheckout}>Checkout</button>
          </div>
        </>
      )}
    </div>
  )
}
