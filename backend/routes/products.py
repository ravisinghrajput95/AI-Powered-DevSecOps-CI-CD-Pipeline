"""Product catalog and search - SQL injection vulnerability"""

from flask import Blueprint, jsonify, request
from sqlalchemy import text

from models.product import Product
from models.user import db

products_bp = Blueprint("products", __name__)


@products_bp.route("/", methods=["GET"])
def list_products():
    category = request.args.get("category")
    query = Product.query
    if category:
        query = query.filter_by(category=category)
    products = query.all()
    return jsonify([p.to_dict() for p in products])


@products_bp.route("/<int:product_id>", methods=["GET"])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())


@products_bp.route("/search", methods=["GET"])
def search_products():
    """VULN: SQL Injection - user input concatenated into raw SQL"""
    search_term = request.args.get("q", "")
    category = request.args.get("category", "")

    # Intentionally vulnerable raw SQL
    sql = f"""
        SELECT id, name, description, price, category, image_url, stock, created_at
        FROM products
        WHERE name ILIKE '%{search_term}%'
    """
    if category:
        sql += f" AND category = '{category}'"

    try:
        result = db.session.execute(text(sql))
        products = []
        for row in result:
            products.append(
                {
                    "id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "price": float(row[3]),
                    "category": row[4],
                    "image_url": Product.resolve_image_url(row[1], row[5]),
                    "stock": row[6],
                    "created_at": str(row[7]) if row[7] else None,
                }
            )
        return jsonify(products)
    except Exception as e:
        # VULN: Verbose error messages expose internal details
        return jsonify({"error": str(e), "query": sql}), 500


@products_bp.route("/", methods=["POST"])
def create_product():
    """VULN: Missing authorization - anyone can create products"""
    data = request.get_json() or {}
    product = Product(
        name=data.get("name", ""),
        description=data.get("description", ""),
        price=data.get("price", 0),
        category=data.get("category", ""),
        image_url=data.get("image_url", ""),
        stock=data.get("stock", 0),
    )
    db.session.add(product)
    db.session.commit()
    return jsonify(product.to_dict()), 201
