#!/usr/bin/env python3
import os
from pathlib import Path
from urllib.request import urlopen, Request

PRODUCT_IMAGE_DOWNLOADS = [
    ('Wireless Headphones', 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/headphones.jpg'),
    ('Smart Watch', 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/smartwatch.jpg'),
    ('Laptop Stand', 'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/laptop-stand.jpg'),
    ('USB-C Hub', 'https://images.unsplash.com/photo-1625723044792-44de16ccb4e9?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/usb-hub.jpg'),
    ('Mechanical Keyboard', 'https://images.unsplash.com/photo-1511467687858-23d96c32e4ae?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/keyboard.jpg'),
    ('Webcam HD', 'https://images.unsplash.com/photo-1519389950473-47ba0277781c?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/webcam.jpg'),
    ('LED Desk Lamp', 'https://images.unsplash.com/photo-1519710164239-da123dc03ef4?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/desk-lamp.jpg'),
    ('Monitor Arm', 'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1200&q=80', 'frontend/public/images/products/monitor-arm.jpg'),
]

BASE_DIR = Path(__file__).resolve().parent.parent


def download_image(url, target_path):
    target_path.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
    })
    with urlopen(req, timeout=30) as response, open(target_path, 'wb') as out_file:
        out_file.write(response.read())


def main():
    print('Downloading product images to local assets...')
    for name, url, rel_path in PRODUCT_IMAGE_DOWNLOADS:
        target = BASE_DIR / rel_path
        print(f'  {name}: {url} -> {target}')
        try:
            download_image(url, target)
            print(f'    saved {target.name} ({target.stat().st_size} bytes)')
        except Exception as exc:
            print(f'    ERROR: {exc}')

if __name__ == '__main__':
    main()
