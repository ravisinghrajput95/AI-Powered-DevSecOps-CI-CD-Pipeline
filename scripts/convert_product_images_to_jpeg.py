#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from PIL import Image

BASE = Path(__file__).resolve().parent.parent
IMAGE_DIR = BASE / 'frontend' / 'public' / 'images' / 'products'
IMG_NAMES = [
    'headphones.jpg',
    'smartwatch.jpg',
    'laptop-stand.jpg',
    'usb-hub.jpg',
    'keyboard.jpg',
    'webcam.jpg',
    'desk-lamp.jpg',
    'monitor-arm.jpg',
]

for name in IMG_NAMES:
    path = IMAGE_DIR / name
    if not path.exists():
        print(f'MISSING: {path}')
        continue
    try:
        with Image.open(path) as img:
            rgb = img.convert('RGB')
            rgb.save(path, format='JPEG', quality=90)
            print(f'Converted {name} to JPEG: {path.stat().st_size} bytes')
    except Exception as exc:
        print(f'ERROR converting {name}: {exc}')
