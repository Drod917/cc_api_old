from .models import Users, Parties, Guestlist, Whitelist, Blacklist, db
from flask import Blueprint, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from random import *
import uuid
import jwt
import datetime

bp = Blueprint('home', __name__)
SECRET_KEY = '72a35b146490347cd93a2ab59b510731'

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'}), 404
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            # current_user = Users.query.filter_by(public_id=data['public_id']).first()
            current_user = Users.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 406

        return f(current_user, *args, **kwargs)
    return decorator


@bp.route('/register', methods=['POST'])
def signup_user(): 
    """Register a new user.
    Creates a new user to login with.
    ---
    parameters:
      - name: name
        in: path
        type: String
        required: true
        default: daniel
      - name: email
        in: path
        type: String
        required: true
        default: test@gmail.com
      - name: password
        in: path
        type: String
        required: true
        default: password!
    responses:
      200:
        description: Registration was successful.
      406:
        description: Email address already exists.
    """
    data = request.get_json() 

    required = ['username', 'password', 'email']
    for word in required:
        if word not in data:
            return jsonify({'message':'data missing from request'}), 404

    hashed_password = generate_password_hash(data['password'], method='sha256')

    exists = Users.query.filter_by(username=data['username']).first()
    if exists:
        return jsonify({'message': 'username already exists'}), 406
    exists = Users.query.filter_by(email=data['email']).first()
    if exists:
        return jsonify(({'message':'email already exists'})), 406

    new_user = Users(username=data['username'], email=data['email'],
                     password=hashed_password)
    db.session.add(new_user) 
    db.session.commit()  

    return jsonify({'message': 'registered successfully'})


@bp.route('/login', methods=['POST']) 
def login_user():
    """Login a user.
    Returns a token to access API resources.

    Requires an Authorization header.
    ---
    parameters:
      - name: email
        in: path
        type: String
        required: true
        default: test@gmail.com
      - name: password
        in: path
        type: String
        required: true
        default: password!
    definitions:
      User:
        type: object
        properties:
          username:
            type: String
          email:
            type: String
          password:
            type: String
    responses:
      200:
        description: Success.
        schema:
          type: String 
          example: '"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."'
      401:
        description: Email or password incorrect.
      404:
        description: User doesn't exist.
    """

    auth = request.authorization  
    if not auth: 
        return make_response('could not verify auth', 401,
                            {'Authentication': 'login required"'})   
    if not auth.username or not auth.password:
        return make_response('could not verify uname or pw', 401, 
                            {'Authentication': 'login required"'})   

    user = Users.query.filter_by(username=auth.username).first()  
    if not user:
        return jsonify({'message': 'user or password is invalid', 'token': ''}), 404

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'username' : user.username, 'exp' : datetime.datetime.utcnow() +
                            datetime.timedelta(minutes=45)}, SECRET_KEY, "HS256")

        return jsonify({'token' : token})

    return jsonify({'message':'user or password is invalid', 'token': ''}), 404 
    # make_response({'message':'user is invalid', 'token':''},  404)
    #    return make_response('could not verify',  401, {'Authentication': '"login required"'})



@bp.route('/users', methods=['GET'])
def get_all_users(): 
    """View all users.
    Returns a dictionary containing every user.
    ---
    responses:
      200:
        description: Success.
    """

    users = Users.query.all()
    result = []  
    for user in users:  
        user_data = {}  
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['password'] = user.password
        
        result.append(user_data)  
    return jsonify({'users': result})

def generate_invite_code():
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    code = ''
    for _ in range(6):
        code += alphabet[randint(0, 51)]
    return code 

# create new party
@bp.route('/party/create', methods=['POST'])
@token_required
def create_party(current_user):
    """Create a new party.
    Adds a new party to the database.

    A valid token must be bundled within the header under "x-access-tokens"
    ---
    parameters:
      - name: name
        type: String
        required: true
      - name: description
        type: String
        required: true
      - name: date
        type: String
        required: true
    definitions:
      Party:
        type: object
        properties:
          name:
            type: String
          description:
            type: String
          date:
            type: String
      Guestlist:
        type: object
        properties:
          username:
            type: User.username
          party_name:
            type: Party.name
    responses:
      404:
        description: No token found. Invalid resource access.
    """

    if (current_user == None):
        return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406
 
    data = request.get_json()

    required = ['name', 'description', 'date']
    for word in required:
        if word not in data:
            return jsonify({'message': 'Invalid payload received'}), 401
    
    # Publicity can be either:
    #  open_with_blacklist 
    # or
    #  whitelist_only
    #
    # Defaults to open_with_blacklist
    if "publicity" not in data:
        publicity = "open_with_blacklist"
    else:
        publicity = data['publicity']

    # check for existing party name
    party_exists = Parties.query.filter_by(name=data['name']).all()
    if party_exists:
        return jsonify({'message': 'Party already exists'}), 406

    # generate invite code
    code = generate_invite_code()

    # check for existing invite code
    code_exists = Parties.query.filter_by(invite_code=code).all()
    while code_exists:
        # generate invite code
        code = generate_invite_code()
        code_exists = Parties.query.filter_by(invite_code=code).all()
        
    new_party = Parties(name=data['name'],
                            description=data['description'],
                            date=data['date'],
                            host=current_user.username,
                            publicity=publicity,
                            invite_code=code)           
    try:
        db.session.add(new_party)  
        db.session.commit() 
    except sqlalchemy.exc.IntegrityError as e:
        return jsonify({'message': 'SQL Integrity Error'}), 406

    # If the party is white list only, add all users to its white list
    if publicity == "whitelist_only" and "whitelist" in data:
        whitelist = data['whitelist']
        for name in whitelist:
            new_guest = Whitelist(party_name=new_party.name,
                                   username=name)
            db.session.add(new_guest)
    else:
        blacklist = data['blacklist']
        for name in blacklist:
            banned_guest = Blacklist(party_name=new_party.name,
                                     username=name)
            db.session.add(banned_guest)
        
    db.session.commit()
    return jsonify({'message' : 'new party created'})


# Returns parties hosted by user associated with TOKEN
@bp.route('/party/host', methods=['GET'])
@token_required
def get_parties(current_user):
    if (current_user == None):
        return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406

    parties = Parties.query.filter_by(host=current_user.username).all()
    output = []
    for party in parties:
        party_data = {}
        party_data['name'] = party.name
        party_data['description'] = party.description
        party_data['date'] = party.date
        party_data['publicity'] = party.publicity
        
        if party.publicity == "whitelist":
            whitelist = []
            guests = Whitelist.query.filter_by(party_name=party.name).all()
            for guest in guests:
                whitelist.append(guest.username)

            party_data['whitelist'] = whitelist
        output.append(party_data)

    return jsonify(output)

# Returns parties that user associated with TOKEN is joined to
@bp.route('/party/guest', methods=['GET'])
@token_required
def get_guests(current_user):
    if (current_user == None):
        return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406

    party_names = []
    guest_in = Guestlist.query.filter_by(username=current_user.username).all()
    if not guest_in:
        return jsonify([]), 404
    for entry in guest_in:
        party_names.append(entry.party_name)
    
    print(party_names)
    output = []
    for party_name in party_names:
        party = Parties.query.filter_by(name=party_name).first()
        party_data = {}
        party_data['name'] = party.name
        party_data['host'] = party.host
        party_data['description'] = party.description
        party_data['date'] = party.date
        output.append(party_data)

    return jsonify(output)


@bp.route('/party/delete', methods=['DELETE'])
@token_required
def delete_party(current_user): 
    if (current_user == None):
        return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406
    data = request.get_json()
    if not data:
        return jsonify({'message': 'no payload received'})
    
    required = 'name'
    if required not in data:
        return jsonify({'message':'no name supplied for deletion'}), 402

    party = Parties.query.filter_by(name=data['name'], host=current_user.username).first()  
    if not party:  
        return jsonify({'message': 'party does not exist'}), 404  

    guestlist = Guestlist.query.filter_by(party_name=data['name']).all()
    for entry in guestlist:
        db.session.delete(entry)

    db.session.delete(party) 
    db.session.commit()  
    return jsonify({'message': 'Party deleted'})



# @bp.route('/party/invite', methods=['POST'])
# @token_required
# def send_invite(current_user):
#     if (current_user == None):
#         return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406

#     data = request.get_json()

#     required = ['party_name', 'guests']
#     for word in required:
#         if word not in data:
#             return jsonify({'message': 'Invalid payload received'}), 401

#     guests = data['guests']
#     for guest in guests:
#         invited = GuestList.query.filter_by(party_name=data['party_name'],
#                                              username=guest).first()
#         if not invited:
#             new_invite = GuestList(party_name=data['party_name'],
#                                 username=guest,
#                                 invited_by=current_user.username,
#                                 invited=True,
#                                 accepted=False,
#                                 banned=False)
#             db.session.add(new_invite)

#     db.session.commit()
#     return jsonify({'message':'guests invited'})

# @bp.route('/party/invite/accept', methods=['POST'])
# @token_required
# def accept_invite(current_user):
#     if (current_user == None):
#         return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406

#     data = request.get_json()

#     if 'party_name' not in data:
#         return jsonify({'message': 'Invalid payload received'}), 401
            
#     user = GuestList.query.filter_by(party_name=data['party_name'],
#                                      username=current_user.username).first()
#     if not user:
#         return jsonify({'message': 'you are the host'})
#     user.invited = False
#     user.accepted = True
    
#     db.session.commit()
#     return jsonify({'message':'invite accepted'})

# @bp.route('/party/invite/pending', methods=['GET'])
# @token_required
# def pending_invites(current_user):
#     if (current_user == None):
#         return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406

            
#     invites = GuestList.query.filter_by(username=current_user.username,
#                                         invited=True,
#                                         accepted=False).all()
#     if not invites:
#         return jsonify([])
#     output = []
#     for invite in invites:
#         output.append(invite.party_name)
    
#     return jsonify(output)

# @bp.route('/parties/<party_id>', methods=['DELETE'])
# @token_required
# def delete_party(current_user, party_id): 
#     if (current_user == None):
#         return jsonify({'message': 'You are not logged in. Invalid resource access.'}), 406

#     party = Parties.query.filter_by(id=party_id, host=current_user.username).first()  
#     if not party:  
#         return jsonify({'message': 'party does not exist'}), 404  

#     guest_list = GuestList.query.filter_by(party_id=party_id).all()
#     for entry in guest_list:
#         db.session.delete(entry)

#     db.session.delete(party) 
#     # db.session.delete(guest_list)
#     db.session.commit()  
#     return jsonify({'message': 'Party deleted'})
 