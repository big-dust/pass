from flask import Blueprint, request, jsonify, current_app
from models import db, AuthCode, Token, User, Client
import datetime
import uuid
from app import redis_client

bp = Blueprint('token', __name__, url_prefix='/token')

@bp.route('/token', methods=['POST'])
def token():
    grant_type = request.form.get('grant_type')
    if grant_type == 'code':
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')

        # 验证客户端 ID 和客户端密钥
        client = Client.query.filter_by(client_id=client_id).first()
        if not client or not client.check_client_secret(client_secret):
            return jsonify({'error': '无效的客户端凭据'}), 400

        auth_code = AuthCode.query.filter_by(code=code).first()
        check_and_delete_code_sha = current_app.config['CHECK_AND_DELETE_CODE_SHA']
        user_id = redis_client.evalsha(check_and_delete_code_sha, 1, f"auth_code:{code}")

        if auth_code and user_id and auth_code.client_id == client_id and auth_code.redirect_uri == redirect_uri:
            user = User.query.get(auth_code.user_id)
            access_token = str(uuid.uuid4())
            refresh_token = str(uuid.uuid4())
            token = Token(access_token=access_token, refresh_token=refresh_token, client_id=client_id, user_id=user.id, expires_in=3600)
            db.session.add(token)
            db.session.commit()
            return jsonify({
                'access_token': token.generate_access_token(),
                'token_type': 'bearer',
                'expires_in': token.expires_in,
                'refresh_token': token.generate_refresh_token()
            })
    return jsonify({'error': '无效的授权'}), 400

# @bp.route('/revoke', methods=['POST'])
# def revoke():
#     data = request.json
#     token = data.get('token')
#     token_entry = Token.query.filter_by(access_token=token).first()
#     if token_entry:
#         db.session.delete(token_entry)
#         db.session.commit()
#         return jsonify({'message': '令牌已成功撤销'})
#     return jsonify({'error': '无效的令牌'}), 400
#
# @bp.route('/refresh', methods=['POST'])
# def refresh_token():
#     grant_type = request.form.get('grant_type')
#     if grant_type == 'refresh_token':
#         refresh_token = request.form.get('refresh_token')
#         client_id = request.form.get('client_id')
#         client_secret = request.form.get('client_secret')
#         token_entry = Token.query.filter_by(refresh_token=refresh_token).first()
#         if token_entry and token_entry.client_id == client_id:
#             new_access_token = str(uuid.uuid4())
#             new_refresh_token = str(uuid.uuid4())
#             token_entry.access_token = new_access_token
#             token_entry.refresh_token = new_refresh_token
#             token_entry.issued_at = datetime.datetime.utcnow()
#             db.session.commit()
#             return jsonify({
#                 'access_token': token_entry.generate_access_token(),
#                 'token_type': 'bearer',
#                 'expires_in': token_entry.expires_in,
#                 'refresh_token': token_entry.generate_refresh_token()
#             })
#     return jsonify({'error': '无效的授权'}), 400
