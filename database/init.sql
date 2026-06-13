-- CloudCart Database Schema
-- Intentionally includes weak defaults for DevSecOps training

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'customer',
    api_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    category VARCHAR(100),
    image_url VARCHAR(500),
    stock INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cart_items (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
    quantity INTEGER DEFAULT 1,
    UNIQUE(user_id, product_id)
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'pending',
    total DECIMAL(10, 2),
    shipping_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER,
    price DECIMAL(10, 2)
);

-- Users are seeded by the Flask app on startup (admin/admin123)
-- Demo credentials are created via registration or app seed

INSERT INTO products (name, description, price, category, image_url, stock) VALUES
('Wireless Headphones', 'Premium noise-cancelling wireless headphones', 149.99, 'Electronics', '/images/products/headphones.jpg', 50),
('Smart Watch', 'Fitness tracking smart watch with heart rate monitor', 299.99, 'Electronics', '/images/products/smartwatch.jpg', 30),
('Laptop Stand', 'Ergonomic aluminum laptop stand', 49.99, 'Accessories', '/images/products/laptop-stand.jpg', 100),
('USB-C Hub', '7-in-1 USB-C hub with HDMI and SD card reader', 39.99, 'Accessories', '/images/products/usb-hub.jpg', 75),
('Mechanical Keyboard', 'RGB mechanical keyboard with Cherry MX switches', 129.99, 'Electronics', '/images/products/keyboard.jpg', 40),
('Webcam HD', '1080p HD webcam with built-in microphone', 79.99, 'Electronics', '/images/products/webcam.jpg', 60),
('LED Desk Lamp', 'LED desk lamp with adjustable brightness', 34.99, 'Home', '/images/products/desk-lamp.jpg', 80),
('Monitor Arm', 'Dual monitor arm mount VESA compatible', 89.99, 'Accessories', '/images/products/monitor-arm.jpg', 25);

-- Reviews seeded after users register via the application
