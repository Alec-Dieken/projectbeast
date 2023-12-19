from os import environ, path
from dotenv import load_dotenv

# Set basedir variable to absolute path of directory containing current file
basedir = path.abspath(path.dirname(__file__))

# Load environment variables from .env file in current directory
load_dotenv(path.join(basedir, ".env"))


# Define Config class to store configuration variables for Flask app
class Config:
    """Setting up Flask config variables"""

    # Flask-related configuration variables
    # Set environment
    FLASK_ENV = "production"
    # Disable testing mode
    TESTING = False
    # Use SECRET_KEY for securely signing cookies and other sensitive data
    SECRET_KEY = environ.get("SECRET_KEY")
    # Set name of folder containing static files
    STATIC_FOLDER = "static"
    # Set name of folder containing HTML templates
    TEMPLATES_FOLDER = "templates"

    # Database-related configuration variables
    # Use URI for database specified in environment variables
    SQLALCHEMY_DATABASE_URI = environ.get("SQLALCHEMY_DATABASE_URI")

    # Disable modification tracking
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email-related configuration variables
    # Allow sending emails
    MAIL_SUPPRESS_SEND = False
    # Set SMTP server to Gmail
    MAIL_SERVER = "smtp.gmail.com"
    # Use port 465 for SMTP server
    MAIL_PORT = 465
    # Disable TLS encryption
    MAIL_USE_TLS = False
    # Enable SSL encryption
    MAIL_USE_SSL = True
    # Set email address to send emails from
    MAIL_USERNAME = "noreply.projectbeast@gmail.com"
    # Load email password from environment variable
    MAIL_PASSWORD = environ.get("MAIL_PASSWORD")
