from flask import Blueprint, request, jsonify
from models import db, Client
import uuid

bp = Blueprint('client', __name__, url_prefix='/client')

@bp.route('/register', methods=['POST'])
def register_client():
    data = request.json
    client_name = data.get('client_name')
    redirect_uri = data.get('redirect_uri')
    existing_client = Client.query.filter_by(client_name=client_name).first()
    if existing_client:
        return jsonify({'error': '客户端已存在'}), 400
    client_id = str(uuid.uuid4())
    client_secret = str(uuid.uuid4())
    client = Client(client_id=client_id, client_name=client_name, redirect_uri=redirect_uri)
    client.set_client_secret(client_secret)
    db.session.add(client)
    db.session.commit()
    return jsonify({'client_id': client_id, 'client_secret': client_secret}), 201
