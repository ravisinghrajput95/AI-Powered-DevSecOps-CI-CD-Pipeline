#!/usr/bin/env python3
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
from app import app
from models.product import Product

with app.app_context():
    for p in Product.query.order_by(Product.id).all():
        print(f'{p.name} -> {p.image_url}')
