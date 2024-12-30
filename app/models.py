from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
db = SQLAlchemy()

#to be changed as per the ER Diagram Provided by the team
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    address_line_1 = db.Column(db.String(120), nullable=False)
    state = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    approved = db.Column(db.Boolean, default=False)
    def __init__(self, password, email, address_line_1, role, firstname, lastname, pincode, state, city):
        self.password = password
        self.email = email
        self.address_line_1 = address_line_1
        self.role = role
        self.firstname = firstname
        self.lastname = lastname
        self.pincode = pincode
        self.state = state
        self.city = city
    
    def isAdmin(self):
        return self.role == 'admin' and self.id == 1 and self.email == "admin@springboard.com"
    
    def isDeliveryPerson(self):
        return self.role.lower() == 'delivery' and self.approved == True

    
# Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    rating = db.Column(db.Float)
    ratting = db.Column(db.String(100))

    def __repr__(self):
        return f'<Product {self.name}>'
