INSERT INTO products
(name, description, price, category, image_url, stock)
SELECT *
FROM (
VALUES
('Wireless Headphones','Premium noise-cancelling wireless headphones',149.99,'Electronics','/images/products/headphones.jpg',50),
('Smart Watch','Fitness tracking smart watch with heart rate monitor',299.99,'Electronics','/images/products/smartwatch.jpg',30),
('Laptop Stand','Ergonomic aluminum laptop stand',49.99,'Accessories','/images/products/laptop-stand.jpg',100),
('USB-C Hub','7-in-1 USB-C hub with HDMI and SD card reader',39.99,'Accessories','/images/products/usb-hub.jpg',75),
('Mechanical Keyboard','RGB mechanical keyboard with Cherry MX switches',129.99,'Electronics','/images/products/keyboard.jpg',40),
('Webcam HD','1080p HD webcam with built-in microphone',79.99,'Electronics','/images/products/webcam.jpg',60),
('LED Desk Lamp','LED desk lamp with adjustable brightness',34.99,'Home','/images/products/desk-lamp.jpg',80),
('Monitor Arm','Dual monitor arm mount VESA compatible',89.99,'Accessories','/images/products/monitor-arm.jpg',25)
) AS seed_data
(name, description, price, category, image_url, stock)
WHERE NOT EXISTS (
    SELECT 1 FROM products
);