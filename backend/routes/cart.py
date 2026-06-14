"""Shopping cart routes"""

from flask import Blueprint, jsonify, request, session

from models.cart import CartItem
from models.product import Product
from models.user import db

cart_bp = Blueprint("cart", __name__)


def get_user_id():
    return (
        session.get("user_id")
        or request.args.get("user_id")
        or request.headers.get("X-User-Id")
    )


@cart_bp.route("/", methods=["GET"])
def get_cart():
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    items = CartItem.query.filter_by(user_id=int(user_id)).all()
    cart = []
    for item in items:
        product = Product.query.get(item.product_id)
        cart.append(
            {
                **item.to_dict(),
                "product": product.to_dict() if product else None,
            }
        )
    return jsonify(cart)


@cart_bp.route("/add", methods=["POST"])
def add_to_cart():
    user_id = get_user_id()
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json() or {}
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    existing = CartItem.query.filter_by(
        user_id=int(user_id), product_id=product_id
    ).first()

    if existing:
        existing.quantity += quantity
    else:
        item = CartItem(user_id=int(user_id), product_id=product_id, quantity=quantity)
        db.session.add(item)

    db.session.commit()
    return jsonify({"message": "Added to cart"})


@cart_bp.route("/remove/<int:item_id>", methods=["DELETE"])
def remove_from_cart(item_id):
    # VULN: Broken access control - no ownership check
    item = CartItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Removed from cart"})


@cart_bp.route("/clear", methods=["POST"])
def clear_cart():
    user_id = get_user_id()
    CartItem.query.filter_by(user_id=int(user_id)).delete()
    db.session.commit()
    return jsonify({"message": "Cart cleared"})
