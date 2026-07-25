"""Shopping cart routes"""

from flask import Blueprint, jsonify, request, session

from models.cart import CartItem
from models.product import Product
from models.user import db
from routes.identity import resolve_user_id

cart_bp = Blueprint("cart", __name__)


@cart_bp.route("/", methods=["GET"])
def get_cart():
    user_id, error = resolve_user_id()
    if error:
        return error

    items = CartItem.query.filter_by(user_id=user_id).all()
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
    user_id, error = resolve_user_id()
    if error:
        return error

    data = request.get_json() or {}
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    # quantity arrives straight from JSON: a string made `existing.quantity
    # += quantity` raise TypeError (500), and a negative value silently
    # corrupted the cart total.
    try:
        quantity = int(quantity)
    except (TypeError, ValueError):
        return jsonify({"error": "quantity must be an integer"}), 400
    if quantity < 1:
        return jsonify({"error": "quantity must be at least 1"}), 400

    if not Product.query.get(product_id):
        return jsonify({"error": "Product not found"}), 404

    existing = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()

    if existing:
        existing.quantity += quantity
    else:
        item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
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
    # Previously called int(get_user_id()) with no guard at all, so an
    # unauthenticated request raised TypeError and returned 500 while every
    # other cart route returned a clean 401.
    user_id, error = resolve_user_id()
    if error:
        return error

    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify({"message": "Cart cleared"})
