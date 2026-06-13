import React, { useEffect, useState } from 'react'
import { cart, products } from '../api/client'
import { useAuth } from '../context/AuthContext'
import ProductCard from '../components/ProductCard'
import './Products.css'

export default function Products() {
  const [items, setItems] = useState([])
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const { user } = useAuth()

  const loadProducts = async () => {
    setLoading(true)
    try {
      const res = search
        ? await products.search(search, category)
        : await products.list(category ? { category } : {})
      setItems(res.data)
    } catch (err) {
      console.error(err)
      setMessage('Unable to load products right now')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadProducts()
  }, [])

  const handleSearch = (e) => {
    e.preventDefault()
    loadProducts()
  }

  const handleAddToCart = async (productId) => {
    if (!user) {
      setMessage('Please login to add items to cart')
      return
    }
    try {
      await cart.add(productId)
      setMessage('Added to cart!')
      setTimeout(() => setMessage(''), 2000)
    } catch (err) {
      setMessage(err.response?.data?.error || 'Failed to add to cart')
    }
  }

  return (
    <div className="container products-page">
      <div className="products-header">
        <div>
          <p className="products-eyebrow">CloudCart Store</p>
          <h1>Product Catalog</h1>
        </div>
        <span className="products-count">{loading ? 'Loading' : `${items.length} items`}</span>
      </div>

      {message && <div className="alert alert-success">{message}</div>}

      <form onSubmit={handleSearch} className="products-toolbar">
        <input
          placeholder="Search products..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All Categories</option>
          <option value="Electronics">Electronics</option>
          <option value="Accessories">Accessories</option>
          <option value="Home">Home</option>
        </select>
        <button type="submit" className="btn btn-primary">Search</button>
      </form>

      {loading ? (
        <div className="products-state">Loading products...</div>
      ) : items.length === 0 ? (
        <div className="products-state">No products found.</div>
      ) : (
        <div className="grid grid-3">
          {items.map((p) => (
            <ProductCard key={p.id} product={p} onAddToCart={handleAddToCart} />
          ))}
        </div>
      )}
    </div>
  )
}
