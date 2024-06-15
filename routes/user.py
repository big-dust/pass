import jwt
from flask import Blueprint, request, jsonify, current_app
from models import db, User
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from extensions import redis_client

bp = Blueprint('user', __name__, url_prefix='/user')

def send_verification_email(email, code):
    sender_email = current_app.config['MAIL_USERNAME']
    sender_password = current_app.config['MAIL_PASSWORD']
    mail_server = current_app.config['MAIL_SERVER']
    mail_port = current_app.config['MAIL_PORT']
    mail_use_tls = current_app.config['MAIL_USE_TLS']

    subject = "邮箱验证码"
    body = f"您的验证码是：{code}"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(mail_server, mail_port)
        if mail_use_tls:
            server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())
        server.quit()
    except Exception as e:
        print(f"Error sending email: {e}")

@bp.route('/send_verification_code', methods=['POST'])
def send_verification_code():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'error': '邮箱是必须的'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': '邮箱已存在'}), 400

    verification_code = str(random.randint(100000, 999999))
    redis_client.setex(f"email_verification_code:{email}", 600, verification_code)

    send_verification_email(email, verification_code)
    return jsonify({'message': '验证码已发送到您的邮箱'}), 200

@bp.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    verification_code = data.get('verification_code')
    avatar = data.get('avatar')  # 获取头像
    nickname = data.get('nickname')  # 获取昵称

    if not email or not password or not verification_code:
        return jsonify({'error': '所有字段都是必须的'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': '邮箱已存在'}), 400

    stored_code = redis_client.get(f"email_verification_code:{email}")
    if not stored_code or stored_code.decode('utf-8') != verification_code:
        return jsonify({'error': '验证码无效或已过期'}), 400

    user = User(email=email, avatar=avatar, nickname=nickname)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    redis_client.delete(f"email_verification_code:{email}")
    return jsonify({'message': '用户注册成功'}), 201

@bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        auth_token = user.generate_auth_token()
        return jsonify({'auth_token': auth_token, 'avatar': user.avatar, 'nickname': user.nickname})
    return jsonify({'error': '无效的凭据'}), 401

@bp.route('/profile', methods=['GET'])
def profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': '未提供认证令牌'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_auth_token(token)
    if not user_id:
        return jsonify({'error': '无效或过期的令牌'}), 401

    user = User.query.get(user_id)
    if user:
        return jsonify({'email': user.email, 'avatar': user.avatar, 'nickname': user.nickname})
    return jsonify({'error': '用户未找到'}), 404

@bp.route('/profile', methods=['PUT'])
def edit_profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': '未提供认证令牌'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_auth_token(token)
    if not user_id:
        return jsonify({'error': '无效或过期的令牌'}), 401

    data = request.json
    avatar = data.get('avatar')
    nickname = data.get('nickname')

    user = User.query.get(user_id)
    if user:
        user.avatar = avatar if avatar else user.avatar
        user.nickname = nickname if nickname else user.nickname
        db.session.commit()
        return jsonify({'message': '用户信息更新成功'})
    return jsonify({'error': '用户未找到'}), 404

def decode_auth_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

