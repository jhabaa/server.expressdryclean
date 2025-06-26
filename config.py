import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("APP_SECRET_KEY")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
    ROOT_FOLDER = os.getenv("ROOT_FOLDER")
    SERVICE_NAME = os.getenv("SERVICE_NAME")
    ALGORITHMS = os.getenv("ALGORITHMS")
    AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
    AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
    AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")

    # MYSQL CONFIG
    MYSQL_USER = os.getenv("MYSQL_USER")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
    MYSQL_HOST = os.getenv("MYSQL_HOST")
    MYSQL_DB = os.getenv("MYSQL_DB")
    MYSQL_PORT = os.getenv("MYSQL_PORT")

    # BABEL CONFIG
    BABEL_PO_FILES_PATH = os.getenv("BABEL_PO_FILES_PATH")
    BABEL_DEFAULT_LOCALE = os.getenv("BABEL_DEFAULT_LOCALE")

    # MAIL CONFIG
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = os.getenv("MAIL_PORT")
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    NOREPLY_EMAIL = os.getenv("NOREPLY_EMAIL")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

    # RECAPTCHA
    RECAPTCHA_SERVER_KEY = os.getenv("RECAPTCHA_SERVER_KEY")
