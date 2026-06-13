import React, { useState, useEffect } from 'react'
import { orders } from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function Orders() {
  const [orderList, setOrderList] = useState([])
  const { user } = useAuth()

  useEffect(() => {
    if (user) {
      orders.list({ user_id: user.id }).then((res) => setOrderList(res.data))
    }
  }, [user])

  if (!user) return <div className="container">Please login to view orders.</div>

  return (
    <div className="container" style={{ padding: '2rem 1rem' }}>
      <h1>My Orders</h1>
      {orderList.length === 0 ? (
        <p>No orders yet.</p>
      ) : (
        orderList.map((order) => (
          <div key={order.id} className="card" style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <h3>Order #{order.id}</h3>
              <span className={`badge badge-${order.status === 'confirmed' ? 'customer' : 'admin'}`}>
                {order.status}
              </span>
            </div>
            <p>Total: ${order.total?.toFixed(2)}</p>
            <p>Date: {order.created_at}</p>
            <p>Address: {order.shipping_address}</p>
          </div>
        ))
      )}
    </div>
  )
}
