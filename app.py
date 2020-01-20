from flask import Flask, request, jsonify, make_response
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from flask_cors import CORS
import os
import uuid
import jwt
from flask_sqlalchemy import SQLAlchemy

# init app
app = Flask(__name__)

CORS(app)
# db setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://wfadnpqa:dwGPR7uApefy9_yEGKrMyY9as9-z8LVv@rajje.db.elephantsql.com:5432/wfadnpqa'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'tracysuproject'

db = SQLAlchemy(app)

from models import Product, User

db.create_all()

# init marshmallow
ma = Marshmallow(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# product schema
class ProductSchema(ma.Schema):
      class Meta:
        fields = ('id', 'name', 'description', 'price', 'qty')
        
# init schema
product_schema = ProductSchema()
products_schema = ProductSchema(many=True)

class UserSchema(ma.Schema):
      class Meta:
        fields = ('public_id', 'username', 'admin')
        
# init schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# routes
@app.route('/product', methods=['POST'])
def add_product():
    
        
    new_product = Product(
        name = request.json['name'],
        description = request.json['description'],
        price = request.json['price'],
        qty = request.json['qty']
    )
        
    db.session.add(new_product)
    db.session.commit()
        
    return product_schema.jsonify(new_product)

@app.route('/products', methods=['GET'])
def get_products():
    all_products = Product.query.all()
    results = products_schema.dump(all_products)
    responseObject = {
        'status': 'success',
        'data': {
            'products': results
        }
    }
    return make_response(jsonify(responseObject)), 200

@app.route('/product/<id>', methods=['GET'])
def get_product(id):
  product = Product.query.get_or_404(id)
  
  return product_schema.jsonify(product)

@app.route('/product/<id>', methods=['PUT'])
def update_product(id):
    try: 
        product = Product.query.get_or_404(id)

        print(request.headers.get('Authorization'))
        
        data = request.get_json()
        
        product.name = data.get('name'),
        product.description = data.get('description'),
        product.price = data.get('price'),
        product.qty = data.get('qty')
        
        db.session.commit()

        responseObject = {
            'status': 'success'
        }
        return make_response(jsonify(responseObject)), 200
    except:
        responseObject = {
            'status': 'error'
        }
        return make_response(jsonify(responseObject)), 401
    

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You dont have access!'})

    users = User.query.all()

    return jsonify({'users' : users_schema.dump(users)})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        responseObject = {
            'status': 'error',
            'message' : 'No user found!'
        }
        
        return make_response(jsonify(responseObject)), 401

    responseObject = {
        'status': 'success',
        'data': {
            'user': user_schema.dump(user)
        }
    }
    
    return make_response(jsonify(responseObject)), 200

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user', methods=['POST'])
def create_user():
    # if not current_user.admin:
    #     return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    
    responseObject = {
            'status': 'success',
            'message' : 'New user created!'
        }
    
    return make_response(jsonify(responseObject)), 200

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()

    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Make sure you enter your username and password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.get('username')).first()

    if not user:
        return make_response('User not found', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({'public_id' : user.public_id}, app.config['SECRET_KEY'])
        
        responseObject = {
            'status': 'success',
            'public_id': user.public_id,
            'token' : token.decode('UTF-8')
        }
    
        return make_response(jsonify(responseObject)), 200

    return make_response('Password wrong', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

# run server
if __name__ == '__main__':
    app.run(debug=True)
    