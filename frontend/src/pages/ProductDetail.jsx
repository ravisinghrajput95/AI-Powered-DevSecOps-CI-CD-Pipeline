import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { products, cart, reviews } from '../api/client'
import { useAuth } from '../context/AuthContext'
import ReviewList from '../components/ReviewList'
import { getProductImage, PLACEHOLDER_IMAGE } from '../utils/productImages'
import './ProductDetail.css'

export default function ProductDetail() {
  const { id } = useParams()
  const [product, setProduct] = useState(null)
  const [imgSrc, setImgSrc] = useState(PLACEHOLDER_IMAGE)
  const [productReviews, setProductReviews] = useState([])
  const [rating, setRating] = useState(5)
  const [comment, setComment] = useState('')
  const [message, setMessage] = useState('')
  const { user } = useAuth()

  useEffect(() => {
    products.get(id).then((res) => {
      setProduct(res.data)
      setImgSrc(getProductImage(res.data))
    })
    reviews.list(id).then((res) => setProductReviews(res.data))
  }, [id])

  const handleAddToCart = async () => {
    if (!user) { setMessage('Please login'); return }
    await cart.add(product.id)
    setMessage('Added to cart!')
  }

  const handleSubmitReview = async (e) => {
    e.preventDefault()
    if (!user) { setMessage('Please login to review'); return }
    await reviews.create({ product_id: parseInt(id), user_id: user.id, rating, comment })
    const res = await reviews.list(id)
    setProductReviews(res.data)
    setComment('')
    setMessage('Review submitted!')
  }

  if (!product) return <div className="container">Loading...</div>

  return (
    <div className="container" style={{ padding: '2rem 1rem' }}>
      {message && <div className="alert alert-success">{message}</div>}
      <div className="card product-detail-card">
        <div className="product-detail-image">
          <img
            src={imgSrc}
            alt={product.name}
            onError={() => setImgSrc(PLACEHOLDER_IMAGE)}
          />
        </div>
        <div>
          <h1>{product.name}</h1>
          <p className="product-category">{product.category}</p>
          <p style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--primary)' }}>
            ${product.price?.toFixed(2)}
          </p>
          <p>{product.description}</p>
          <p>Stock: {product.stock}</p>
          <button className="btn btn-primary" onClick={handleAddToCart}>Add to Cart</button>
        </div>
      </div>

      <h2>Reviews</h2>
      <ReviewList reviews={productReviews} />

      {user && (
        <form onSubmit={handleSubmitReview} className="card" style={{ marginTop: '1rem' }}>
          <h3>Write a Review</h3>
          <div className="form-group">
            <label>Rating</label>
            <select value={rating} onChange={(e) => setRating(parseInt(e.target.value))}>
              {[5,4,3,2,1].map((r) => <option key={r} value={r}>{r} stars</option>)}
            </select>
          </div>
          <div className="form-group">
            <label>Comment</label>
            <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={3} />
          </div>
          <button type="submit" className="btn btn-primary">Submit Review</button>
        </form>
      )}
    </div>
  )
}
