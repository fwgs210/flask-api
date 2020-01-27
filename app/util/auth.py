import jwt
from app.models.model import User
from app.main import app

def token_decode(token): 
    if not token:
        return None

    try: 
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(public_id=data['public_id']).first()
        return current_user
    except:
        return None