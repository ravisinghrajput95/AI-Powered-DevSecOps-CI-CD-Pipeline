#!/usr/bin/env python3
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
from app import app, db
from models.product import Product

IMAGE_URL_UPDATES = {
    'Wireless Headphones': '/images/products/headphones.jpg',
    'Smart Watch': '/images/products/smartwatch.jpg',
    'Laptop Stand': '/images/products/laptop-stand.jpg',
    'USB-C Hub': '/images/products/usb-hub.jpg',
    'Mechanical Keyboard': '/images/products/keyboard.jpg',
    'Webcam HD': '/images/products/webcam.jpg',
    'Desk Lamp': '/images/products/desk-lamp.jpg',
    'Monitor Arm': '/images/products/monitor-arm.jpg',
}

with app.app_context():
    for name, url in IMAGE_URL_UPDATES.items():
        product = Product.query.filter_by(name=name).first()
        if product:
            product.image_url = url
            print(f'Updated {name}')
        else:
            print(f'Missing product: {name}')
    db.session.commit()
    print('Database image_url fields updated.')
