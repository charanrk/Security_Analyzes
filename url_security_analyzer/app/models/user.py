from . import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def __init__(self, email, password, name=None):
        self.email = email
        self.password = password
        self.name = name
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit() 