from functools import wraps
from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import datetime
import jwt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SECRET_KEY'] = 'SECRET_KEY'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    user_name = db.Column(db.String(100))
    password = db.Column(db.String(100))  

    def __init__(self, email, user_name, password):
        self.email = email
        self.user_name = user_name
        self.password = password

blacklisted_tokens = set()

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.cookies.get('access_token_cookie')

        if not token:
            return jsonify({'msg': 'Token not found'}), 401

        if is_token_blacklisted(token):
            return jsonify({'msg': 'Token is no longer valid'}), 401

        try:
            user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(user_data['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'msg': 'Token is expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'msg': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'msg': 'Error decoding token', 'error': str(e)}), 401

        return f(user, *args, **kwargs)

    return decorator

@app.route('/register', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    user_name = data.get('user_name')
    password = data.get('password')

    if not email or not user_name or not password:
        return jsonify({"msg": "Missing fields"}), 400

    hashed_password = generate_password_hash(password)  
    new_user = User(email=email, user_name=user_name, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User Created Successfully"})

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Missing credentials"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "Invalid credentials"}), 401

    access_token = jwt.encode(
    {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=120)},app.config['SECRET_KEY'], algorithm='HS256'
    )

    response = make_response(jsonify({'msg': 'Login successful'}))
    response.set_cookie('access_token_cookie', access_token, httponly=True)
    return response

@app.route('/logout', methods=["GET"])
@token_required
def logout(user):
    response = make_response(jsonify({"msg": "Successfully logged out"}))
    response.set_cookie('access_token_cookie', '', expires=0) 
    return response

def is_token_blacklisted(token):
    return token in blacklisted_tokens

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8000, use_reloader=False)
