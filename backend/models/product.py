from models.user import db


class Product(db.Model):
    __tablename__ = "products"

    DEFAULT_IMAGE_URL = "/images/products/product-placeholder.jpg"
    IMAGE_MAP = {
        "Wireless Headphones": "/images/products/headphones.jpg",
        "Smart Watch": "/images/products/smartwatch.jpg",
        "USB-C Hub": "/images/products/usb-hub.jpg",
        "Webcam HD": "/images/products/webcam.jpg",
        "Monitor Arm": "/images/products/monitor-arm.jpg",
        "Mechanical Keyboard": "/images/products/keyboard.jpg",
        "Desk Lamp": "/images/products/desk-lamp.jpg",
        "LED Desk Lamp": "/images/products/desk-lamp.jpg",
        "Laptop Stand": "/images/products/laptop-stand.jpg",
    }

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    category = db.Column(db.String(100))
    image_url = db.Column(db.String(500))
    stock = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    @classmethod
    def resolve_image_url(cls, name, image_url=None):
        return image_url or cls.IMAGE_MAP.get(name) or cls.DEFAULT_IMAGE_URL

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price": float(self.price),
            "category": self.category,
            "image_url": self.resolve_image_url(self.name, self.image_url),
            "stock": self.stock,
            "created_at": str(self.created_at) if self.created_at else None,
        }
