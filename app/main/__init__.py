from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# init app
app = Flask(__name__)


# db setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://wfadnpqa:dwGPR7uApefy9_yEGKrMyY9as9-z8LVv@rajje.db.elephantsql.com:5432/wfadnpqa'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'tracysuproject'
app.config.SWAGGER_UI_DOC_EXPANSION = 'list'

db = SQLAlchemy(app)

CORS(app)