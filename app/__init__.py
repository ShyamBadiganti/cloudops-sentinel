from flask import Flask
from dotenv import load_dotenv
load_dotenv()
def create_app():
    app = Flask(__name__)
    from app.routes.main import main_bp
    from app.routes.health import health_bp
    from app.routes.aws import aws_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(aws_bp)
    return app
