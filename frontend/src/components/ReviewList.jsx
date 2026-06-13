import React from 'react'

/**
 * VULN: XSS - renders user comments as raw HTML without sanitization
 */
export default function ReviewList({ reviews }) {
  if (!reviews?.length) {
    return <p className="no-reviews">No reviews yet. Be the first!</p>
  }

  return (
    <div className="reviews-list">
      {reviews.map((review) => (
        <div key={review.id} className="review-item card">
          <div className="review-header">
            <span className="review-rating">{'★'.repeat(review.rating)}{'☆'.repeat(5 - review.rating)}</span>
            <span className="review-date">{review.created_at}</span>
          </div>
          {/* VULN: dangerouslySetInnerHTML allows stored XSS */}
          <div
            className="review-comment"
            dangerouslySetInnerHTML={{ __html: review.comment }}
          />
        </div>
      ))}
    </div>
  )
}
