from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # public_id = db.Column(db.Integer)
    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(32))

class Parties(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.Integer, db.ForeignKey('users.username'), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(256), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    publicity = db.Column(db.String(20), nullable=False)
    invite_code = db.Column(db.String(6), nullable=False, unique=True)


# Defines the relation between guests and associated parties
class Guestlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    party_name = db.Column(db.Integer, db.ForeignKey('parties.name'), nullable=False)
    username = db.Column(db.Integer, db.ForeignKey('users.username'), nullable=False)

# If party is closed, members here are allowed on the guest list
class Whitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    party_name = db.Column(db.Integer, db.ForeignKey('parties.name'), nullable=False)
    username = db.Column(db.Integer, db.ForeignKey('users.username'), nullable=False)

# If party is open, members here are banned from the guest list
class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    party_name = db.Column(db.Integer, db.ForeignKey('parties.name'), nullable=False)
    username = db.Column(db.Integer, db.ForeignKey('users.username'), nullable=False)
