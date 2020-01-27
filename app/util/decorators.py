from flask import request, jsonify
from functools import wraps
from .auth import token_decode

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            
        data = token_decode(token)

        if not data:
            return {'message' : 'Token is missing or invalid!'}, 401

        return f(*args, **kwargs)

    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            
        data = token_decode(token)

        if not data:
            return {'message' : 'Token is missing or invalid!'}, 401
        
        if not data.admin:
            return {'message' : 'You dont have admin access!'}, 401

        return f(*args, **kwargs)

    return decorated