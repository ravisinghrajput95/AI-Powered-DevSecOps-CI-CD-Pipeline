"""Order management routes"""

from flask import Blueprint, jsonify, request, session

from models.cart import CartItem
from models.order import Order, OrderItem
from models.product import Product
from models.user import db

orders_bp = Blueprint("orders", __name__)


@orders_bp.route("/", methods=["GET"])
def list_orders():
    user_id = session.get("user_id") or request.args.get("user_id")
    # VULN: IDOR - can list any user's orders via user_id param
    if request.args.get("all") == "true":
        orders = Order.query.all()
    elif user_id:
        orders = Order.query.filter_by(user_id=int(user_id)).all()
    else:
        orders = Order.query.all()
    return jsonify([o.to_dict() for o in orders])


@orders_bp.route("/<int:order_id>", methods=["GET"])
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    items = OrderItem.query.filter_by(order_id=order_id).all()
    return jsonify(
        {
            **order.to_dict(),
            "items": [i.to_dict() for i in items],
        }
    )


@orders_bp.route("/checkout", methods=["POST"])
def checkout():
    data = request.get_json() or {}
    user_id = session.get("user_id") or data.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    cart_items = CartItem.query.filter_by(user_id=int(user_id)).all()

    if not cart_items:
        return jsonify({"error": "Cart is empty"}), 400

    total = 0
    order = Order(
        user_id=int(user_id),
        status="pending",
        shipping_address=data.get("shipping_address", ""),
    )
    db.session.add(order)
    db.session.flush()

    for item in cart_items:
        product = Product.query.get(item.product_id)
        if product:
            total += float(product.price) * item.quantity
            order_item = OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                quantity=item.quantity,
                price=product.price,
            )
            db.session.add(order_item)

    order.total = total
    order.status = "confirmed"
    CartItem.query.filter_by(user_id=int(user_id)).delete()
    db.session.commit()

    return jsonify(order.to_dict()), 201


@orders_bp.route("/<int:order_id>/status", methods=["PUT"])
def update_order_status(order_id):
    """VULN: Missing authorization - any user can update order status"""
    data = request.get_json() or {}
    order = Order.query.get_or_404(order_id)
    order.status = data.get("status", order.status)
    db.session.commit()
    return jsonify(order.to_dict())
