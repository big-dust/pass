from flask import Blueprint, request, redirect, jsonify, render_template, url_for, current_app
import uuid
from models import db, AuthCode, User, Client
import jwt
from config import Config
from extensions import redis_client

bp = Blueprint('auth', __name__, url_prefix='/auth')

def decode_auth_token(token):
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@bp.route('/authorize', methods=['GET'])
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    client = Client.query.filter_by(client_id=client_id).first()
    if not client or client.redirect_uri != redirect_uri:
        return jsonify({'error': '无效的客户端ID或重定向URI'}), 400
    return render_template('authorize.html', client_id=client_id, redirect_uri=redirect_uri, state=state)

@bp.route('/authorize', methods=['POST'])
def authorize_post():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': '未提供认证令牌'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_auth_token(token)
    if not user_id:
        return jsonify({'error': '无效或过期的令牌'}), 401

    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    decision = request.form.get('decision')

    client = Client.query.filter_by(client_id=client_id).first()
    if not client or client.redirect_uri != redirect_uri:
        return jsonify({'error': '无效的客户端ID或重定向URI'}), 400

    if decision == 'allow':
        code = str(uuid.uuid4())
        auth_code = AuthCode(code=code, client_id=client_id, redirect_uri=redirect_uri, user_id=user_id)
        db.session.add(auth_code)
        db.session.commit()
        # 将授权码存储在 Redis 中，并设置有效期为 10 分钟
        redis_client.setex(f"auth_code:{code}", 600, user_id)
        return redirect(f'{redirect_uri}?code={code}&state={state}')
    elif decision == 'deny':
        return redirect(f'{redirect_uri}?error=access_denied&state={state}')
    else:
        return jsonify({'error': '无效的决策'}), 400

@bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')
