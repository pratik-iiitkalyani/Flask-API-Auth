from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # To Generate Random Id
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/API-Auth'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # print("zfghjf")
        token = None

        if 'x-access-token' in request.headers:
            # print("x-access-token", x-access-token)
            token = request.headers['x-access-token']
            print("token", token)
        if not token:
            return jsonify({'message': "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print("data", data)
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message": "Token is Invalid"}), 401
        return f(create_user, *args, **kwargs)
    return decorated

@app.route('/user', methods = ['GET'])
@token_required
def get_all_user(current_user):
    # print("current", current_user.admin)
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action'})

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({"users": output})

@app.route('/user/<public_id>', methods = ['GET'])
@token_required
def get_user_by_id(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':'No User found'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify(user_data)

@app.route('/user', methods = ['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action'})
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name = data['name'], password = hashed_password, admin = False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'new user created'})



@app.route('/user/<public_id>', methods = ['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':'No User found'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})

@app.route('/user/<public_id>', methods = ['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':'No User found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "user has been deleted"})


@app.route('/login', methods = ['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW.Authenticate' : 'Basic realm="Login Required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return jsonify({'message':'No User found'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
         app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW.Authenticate' : 'Basic realm="Login Required!"'})


if __name__ == '__main__':
    app.run(debug=True)