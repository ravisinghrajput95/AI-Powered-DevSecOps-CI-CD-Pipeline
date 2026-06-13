const PRODUCT_IMAGE_MAP = {
  'Wireless Headphones': '/images/products/headphones.jpg',
  'Smart Watch': '/images/products/smartwatch.jpg',
  'USB-C Hub': '/images/products/usb-hub.jpg',
  'Webcam HD': '/images/products/webcam.jpg',
  'Monitor Arm': '/images/products/monitor-arm.jpg',
  'Mechanical Keyboard': '/images/products/keyboard.jpg',
  'Desk Lamp': '/images/products/desk-lamp.jpg',
  'LED Desk Lamp': '/images/products/desk-lamp.jpg',
  'Laptop Stand': '/images/products/laptop-stand.jpg',
}

export const PLACEHOLDER_IMAGE = '/images/products/product-placeholder.jpg'

export function getProductImage(product = {}) {
  return product.image_url || PRODUCT_IMAGE_MAP[product.name] || PLACEHOLDER_IMAGE
}
