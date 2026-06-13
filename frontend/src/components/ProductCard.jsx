import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getProductImage, PLACEHOLDER_IMAGE } from '../utils/productImages'
import './ProductCard.css'

function getDescription(description) {
  if (!description) return 'No description available.'
  return description.length > 78 ? `${description.substring(0, 78)}...` : description
}

export default function ProductCard({ product, onAddToCart }) {
  const [imgSrc, setImgSrc] = useState(getProductImage(product))
  const [isLoading, setIsLoading] = useState(true)
  const isOutOfStock = Number(product.stock) <= 0

  useEffect(() => {
    setImgSrc(getProductImage(product))
    setIsLoading(true)
  }, [product.image_url, product.name])

  const handleImageLoad = () => {
    setIsLoading(false)
  }

  const handleImageError = () => {
    if (imgSrc !== PLACEHOLDER_IMAGE) {
      setImgSrc(PLACEHOLDER_IMAGE)
      setIsLoading(true)
    } else {
      setIsLoading(false)
    }
  }

  return (
    <article className="product-card card">
      <Link to={`/products/${product.id}`} className="product-image" aria-label={`View ${product.name}`}>
        <div className="product-image-wrapper">
          {isLoading && <div className="image-skeleton" />}
          <img
            src={imgSrc}
            alt={product.name}
            onLoad={handleImageLoad}
            onError={handleImageError}
            className={isLoading ? 'loading' : 'loaded'}
          />
        </div>
      </Link>

      <div className="product-info">
        <span className="product-category">{product.category}</span>
        <h3>
          <Link to={`/products/${product.id}`}>{product.name}</Link>
        </h3>
        <p className="product-desc">{getDescription(product.description)}</p>

        <div className="product-footer">
          <span className="product-price">${product.price?.toFixed(2)}</span>
          <button
            className="btn btn-primary product-action"
            disabled={isOutOfStock}
            onClick={() => onAddToCart?.(product.id)}
          >
            {isOutOfStock ? 'Out of Stock' : 'Add to Cart'}
          </button>
        </div>
      </div>
    </article>
  )
}
