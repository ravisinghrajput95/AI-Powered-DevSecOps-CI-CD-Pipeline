from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255))
    role = db.Column(db.String(50), default="customer")
    api_key = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self, include_sensitive=False):
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "created_at": str(self.created_at) if self.created_at else None,
        }
        # VULN: Sensitive information exposure
        if include_sensitive:
            data["password_hash"] = self.password_hash
            data["api_key"] = self.api_key
        return data
