from flask import request, jsonify, make_response
from flask_restplus import Api, Resource, fields
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import uuid
import jwt
from app.main import app, db
from app.models.model import Product, User
from app.util.decorators import token_required, admin_required
from app.util.auth import token_decode

authorizations = {
    'user_token': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'x-access-token'
    }
}

api = Api(app, authorizations=authorizations,
    security='user_token',)

# init marshmallow
ma = Marshmallow(app)

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



user_login_model = api.model('User_Login', {
    'username': fields.String(required=True, description='user username'),
    'password': fields.String(required=True, description='user password')
})

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
    

@api.route('/users')
class AllUsers(Resource):
    @api.doc('auth_token')
    @admin_required
    def get(self):
        current_user = token_decode(request.headers['x-access-token'])
        
        if not current_user.admin:
            return jsonify({'message' : 'You dont have access!'})

        users = User.query.all()

        return {'users' : users_schema.dump(users)}, 200


@api.route('/user/<public_id>')
class UserById(Resource):
    @api.doc('auth_token')
    @token_required
    def get(self, public_id):

        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            responseObject = {
                'status': 'error',
                'message' : 'No user found!'
            }
            
            return responseObject, 401
        
        return {
            'status': 'success',
            'user': user_schema.dump(user)
        }, 200

    @api.doc('auth_token')
    @admin_required
    def put(self, public_id):
        user = User.query.filter_by(public_id=public_id).first()

        if not user:
            return {'message' : 'No user found!'}, 401

        user.admin = True
        db.session.commit()

        return {'message' : 'The user has been promoted!'}, 200

    @api.doc('auth_token')
    @admin_required
    def delete(self, public_id):   
             
        user = User.query.filter_by(public_id=public_id).delete()
        db.session.commit()

        return {'message' : 'The user has been deleted.'}, 200
    

@api.route('/register')
class Register(Resource):
    @api.expect(user_login_model, validate=True)
    def post(self):

        data = request.get_json()

        hashed_password = generate_password_hash(data['password'], method='sha256')

        new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
        
        responseObject = {
                'status': 'success',
                'message' : 'New user created!'
            }
        
        return responseObject, 201


# @api.route('/login')
# class UserLogin(Resource):
#     """
#         User Login Resource
#     """
#     @api.doc('user login')
#     @api.expect(user_auth, validate=True)
#     def post(self):
#         # get the post data
#         post_data = request.json
#         return Auth.login_user(data=post_data)


@api.route('/login')
class Login(Resource):
    @api.expect(user_login_model, validate=True)
    def post(self):
        auth = api.payload

        if not auth or not auth.get('username') or not auth.get('password'):
            return make_response('Make sure you enter your username and password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

        user = User.query.filter_by(username=auth.get('username')).first()

        if not user:
            return make_response('User not found', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

        if check_password_hash(user.password, auth.get('password')):
            token = jwt.encode({'public_id' : user.public_id}, app.config['SECRET_KEY'])
                    
            return {
                'status': 'success',
                'public_id': user.public_id,
                'access': 'member' if not user.admin else 'admin',
                'token' : token.decode('UTF-8')
            }, 200

        return make_response('Password wrong', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

# run server
if __name__ == '__main__':
    app.run(debug=True)
    