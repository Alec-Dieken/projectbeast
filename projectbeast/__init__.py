from flask import Flask
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth


# Globally accessible libraries
socketio = SocketIO()
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
oauth = OAuth()


def init_app():
    '''Initialize core application'''
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object('config.Config')

    # Initialize SocketIO
    socketio.init_app(app)
    socketio.cors_allowed_origins = '*'
    socketio.engineio_logger = True
    socketio.logger = True

    # Initialize SQLAlchemy
    db.init_app(app)

    # Initialize Bcrypt
    bcrypt.init_app(app)

    # Initialize LoginManager
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = ""

    # Initialize Mail
    mail.init_app(app)

    # Initialize OAuth
    oauth.init_app(app)

    # Import Routes and return app
    with app.app_context():
        from . import routes

        return app
