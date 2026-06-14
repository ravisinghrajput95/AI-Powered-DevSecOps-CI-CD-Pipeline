"""Product reviews - XSS stored in comments"""

from flask import Blueprint, jsonify, request, session

from models.review import Review
from models.user import db

reviews_bp = Blueprint("reviews", __name__)


@reviews_bp.route("/product/<int:product_id>", methods=["GET"])
def get_reviews(product_id):
    reviews = Review.query.filter_by(product_id=product_id).all()
    return jsonify([r.to_dict() for r in reviews])


@reviews_bp.route("/", methods=["POST"])
def create_review():
    data = request.get_json() or {}
    user_id = session.get("user_id") or data.get("user_id")

    review = Review(
        product_id=data.get("product_id"),
        user_id=user_id,
        rating=data.get("rating", 5),
        # VULN: XSS - comment stored and returned without sanitization
        comment=data.get("comment", ""),
    )
    db.session.add(review)
    db.session.commit()
    return jsonify(review.to_dict()), 201


@reviews_bp.route("/<int:review_id>", methods=["DELETE"])
def delete_review(review_id):
    # VULN: Missing authorization
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    return jsonify({"message": "Review deleted"})
