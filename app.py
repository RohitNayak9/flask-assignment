
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import uuid  # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
app = Flask(__name__)
app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:root@localhost/postdata'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

class Banks(db.Model):
    __tablename__ = 'banks'
    id = db.Column(db.Integer, primary_key=True)
    name = db. Column(db.String(100), nullable=False)

    def __repr__(self):
        return "<Banks %r>" % self.name


class Branches(db.Model):
    __tablename__ = 'branches'
    id = db.Column(db.Integer, primary_key=True)
    ifsc = db. Column(db.String(100), nullable=False, primary_key=True)
    bank_id = db.Column(db.Integer, db.ForeignKey('Banks.id'), nullable=False)
    branch = db.Column(db.Integer(), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    city = db. Column(db.String(100), nullable=False)
    district = db. Column(db.String(100), nullable=False)
    state = db. Column(db.String(100), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))

# decorator for verifying the JWT


def jwt_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id=data['public_id'])\
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated

# User Database Route
# this route sends back list of users users


@app.route('/user', methods=['GET'])
@jwt_token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output})

# route for logging user in


@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query\
        .filter_by(email=auth.get('email'))\
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(days=5)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token': token.decode('UTF-8')}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )

# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    user = User.query\
        .filter_by(email=email)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


@app.route('/getbanks', methods=['GET'])
@jwt_token_required
def getbanks():
    all_banks = []
    banks = Banks.query.all()
    for bank in banks:
         results = {
             "bank_id": bank.id,
             "name": bank.name}
         all_banks.append(results)

    return jsonify(
         {
             "success": True,
             "banks": all_banks,
             "total_banks": len(banks),
         }
     )

@app.route('/getbranches', methods=['GET'])
@jwt_token_required
def getbranches():
    #GET API to fetch a bank details, given branch IFSC code
    limit=int(request.GET['limit'])
    offset=int(request.GET['offset'])
    ifsc = request.GET['ifsc']

    all_branches = []
    branches = Branches.query.limit(limit).offset(offset).filter_by(ifsc=ifsc)
    for branch in branches:
        banks = Banks.query.filter_by(id=branch.bank_id)
        results = {
             "ifsc": branch.ifsc,
             "branch": branch.branch,
             "bank_id": branch.bank_id,
             "address": branch.address,
             "state": branch.state,
             "city": branch.city, 
             "bank_detail":banks}

        all_branches.append(results)

    return jsonify(
         {
             "success": True,
             "branches": all_branches,
             "total_branches": len(branches),
         }
     )


@app.route('/getbranches', methods=['GET'])
@jwt_token_required
def getbranches():
    #GET API to fetch a bank details, given branch IFSC code
    limit = int(request.GET['limit'])
    offset = int(request.GET['offset'])
    ifsc = request.GET['ifsc']

    all_branches = []
    branches = Branches.query.limit(limit).offset(offset).filter_by(ifsc=ifsc)
    for branch in branches:
        banks = Banks.query.filter_by(id=branch.bank_id)
        results = {
            "ifsc": branch.ifsc,
            "branch": branch.branch,
            "bank_id": branch.bank_id,
            "address": branch.address,
            "state": branch.state,
            "city": branch.city,
            "bank_detail": banks}

        all_branches.append(results)

    return jsonify(
        {
            "success": True,
            "branches": all_branches,
            "total_branches": len(branches),
        }
    )


@app.route('/getbranchesbynamecity', methods=['GET'])
@jwt_token_required
def getbranchesbynamecity():
    #.limit(limit).offset(offset).
    limit = int(request.GET['limit'])
    offset = int(request.GET['offset'])
    city = request.GET['city']
    name = request.GET['name']


    all_branches = []
    branches = meta.Session.query(User).limit(limit).offset(offset).filter(
        Branches.city.like(city),
        Branches.name.like(name)
    )
    for branch in branches:
        
        results = {
            "ifsc": branch.ifsc,
            "branch": branch.branch,
            "bank_id": branch.bank_id,
            "address": branch.address,
            "state": branch.state,
            "city": branch.city,
           }

        all_branches.append(results)

    return jsonify(
        {
            "success": True,
            "branches": all_branches,
            "total_branches": len(branches),
        }
    )




if __name__ == '__main__':
    app.run(debug=True)
