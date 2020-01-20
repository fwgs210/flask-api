from flask_sqlalchemy import SQLAlchemy
from __main__ import app

# init db
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    
    def __repr__(self):
        return '<Task %r>' % self.id


# product 
class Product(db.Model):
    id = db.Column(db.Integer, primary_key =True)
    name = db.Column(db.String(100), unique=True)
    description = db.Column(db.String(200))
    price = db.Column(db.Float)
    qty = db.Column(db.Integer)
    
    def __repr__(self):
        return '<Task %r>' % self.id
    
    # def __init__(self, name, description, price, qty):
    #     self.name = name
    #     self.description = description
    #     self.price = price
    #     self.qty = qty

db.create_all()