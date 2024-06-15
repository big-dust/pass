from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from config import Config

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)  # 邮箱字段
    password_hash = db.Column(db.String(128))
    avatar = db.Column(db.String(256))  # 头像字段
    nickname = db.Column(db.String(64))  # 昵称字段

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=3600):
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
            'iat': datetime.datetime.utcnow(),
            'sub': self.id
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, index=True)
    client_secret = db.Column(db.String(128))
    client_name = db.Column(db.String(64))
    redirect_uri = db.Column(db.String(256))

    def set_client_secret(self, client_secret):
        self.client_secret = generate_password_hash(client_secret)

    def check_client_secret(self, client_secret):
        return check_password_hash(self.client_secret, client_secret)

class AuthCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(128), index=True, unique=True)
    client_id = db.Column(db.String(64))
    redirect_uri = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(256), index=True, unique=True)
    refresh_token = db.Column(db.String(256), index=True, unique=True)
    client_id = db.Column(db.String(64))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    expires_in = db.Column(db.Integer)
    issued_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def is_expired(self):
        return datetime.datetime.utcnow() > self.issued_at + datetime.timedelta(seconds=self.expires_in)

    def generate_access_token(self):
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=self.expires_in),
            'iat': datetime.datetime.utcnow(),
            'sub': self.user_id
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

    def generate_refresh_token(self):
        payload = {
            'iat': datetime.datetime.utcnow(),
            'sub': self.user_id
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')
