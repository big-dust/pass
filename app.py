from flask import Flask, jsonify, request
from flask_migrate import Migrate
from models import db
from config import Config
from extensions import redis_client
import time
from functools import wraps

class RateLimiter:
    def __init__(self, redis_client, max_requests, window_seconds):
        self.redis_client = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def is_allowed(self, key):
        current_time = int(time.time())
        window_start = current_time - self.window_seconds
        pipeline = self.redis_client.pipeline()

        # 移除窗口之外的请求
        pipeline.zremrangebyscore(key, 0, window_start)
        # 获取当前窗口中的请求数
        pipeline.zcard(key)
        # 添加当前请求
        pipeline.zadd(key, {current_time: current_time})
        # 设置键的过期时间
        pipeline.expire(key, self.window_seconds)

        results = pipeline.execute()
        current_count = results[1]  # 获取当前请求数

        if current_count > self.max_requests:
            return False
        return True

    def limit(self, key_func):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                key = key_func()
                if not self.is_allowed(key):
                    return jsonify({'error': '请求过多，请稍后再试'}), 429
                return func(*args, **kwargs)
            return wrapper
        return decorator

rate_limiter = RateLimiter(redis_client, max_requests=60, window_seconds=60)
global_rate_limiter = RateLimiter(redis_client, max_requests=1000, window_seconds=60)

def get_client_ip():
    return request.remote_addr

def global_key():
    return 'global'

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate = Migrate(app, db)
    redis_client.init_app(app)

    with app.app_context():
        # 示例设置
        redis_client.setex(f"auth_code:", 600, 1)
        # 加载 Lua 脚本
        with open('scripts/check_and_delete_code.lua', 'r') as file:
            check_and_delete_code_script = file.read()
        app.config['CHECK_AND_DELETE_CODE_SHA'] = redis_client.script_load(check_and_delete_code_script)

    from routes import auth, token, user, client
    app.register_blueprint(auth.bp)
    app.register_blueprint(token.bp)
    app.register_blueprint(user.bp)
    app.register_blueprint(client.bp)

    @app.before_request
    def before_request():
        if not global_rate_limiter.is_allowed(global_key()):
            return jsonify({'error': '全局请求过多，请稍后再试'}), 429
        if not rate_limiter.is_allowed(get_client_ip()):
            return jsonify({'error': '单 IP 请求过多，请稍后再试'}), 429

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=8080)
