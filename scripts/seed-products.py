#!/usr/bin/env python3
"""Seed sample products if database is empty."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app import app, db
from models.product import Product

SAMPLE_PRODUCTS = [
    ("Wireless Headphones", "Premium noise-cancelling wireless headphones", 149.99, "Electronics", "/images/products/headphones.jpg", 50),
    ("Smart Watch", "Fitness tracking smart watch", 299.99, "Electronics", "/images/products/smartwatch.jpg", 30),
    ("Laptop Stand", "Ergonomic aluminum laptop stand", 49.99, "Accessories", "/images/products/laptop-stand.jpg", 100),
    ("USB-C Hub", "7-in-1 USB-C hub", 39.99, "Accessories", "/images/products/usb-hub.jpg", 75),
    ("Mechanical Keyboard", "RGB mechanical keyboard", 129.99, "Electronics", "/images/products/keyboard.jpg", 40),
    ("LED Desk Lamp", "LED desk lamp", 34.99, "Home", "/images/products/desk-lamp.jpg", 80),
    ("Webcam HD", "1080p HD webcam", 79.99, "Electronics", "/images/products/webcam.jpg", 60),
    ("Monitor Arm", "Dual monitor arm mount VESA compatible", 89.99, "Accessories", "/images/products/monitor-arm.jpg", 25),
]

with app.app_context():
    if Product.query.count() == 0:
        for name, desc, price, cat, image_url, stock in SAMPLE_PRODUCTS:
            db.session.add(
                Product(
                    name=name,
                    description=desc,
                    price=price,
                    category=cat,
                    image_url=image_url,
                    stock=stock,
                )
            )
        db.session.commit()
        print("Seeded sample products.")
    else:
        print(f"Database already has {Product.query.count()} products.")
