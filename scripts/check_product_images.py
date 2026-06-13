#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from PIL import Image

BASE = Path(__file__).resolve().parent.parent
IMAGE_DIR = BASE / 'frontend' / 'public' / 'images' / 'products'

for path in sorted(IMAGE_DIR.glob('*.jpg')):
    try:
        with Image.open(path) as img:
            print(f'{path.name}: {img.format} {img.size} {img.mode}')
    except Exception as exc:
        print(f'{path.name}: ERROR {exc}')
