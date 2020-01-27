from app.main import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    
    def __repr__(self):
        return '<User %r>' % self.id


# product 
class Product(db.Model):
    id = db.Column(db.Integer, primary_key =True)
    name = db.Column(db.String(100), unique=True)
    description = db.Column(db.String(200))
    price = db.Column(db.Float)
    qty = db.Column(db.Integer)
    
    def __repr__(self):
        return '<Prodcut %r>' % self.id


db.create_all()