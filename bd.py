import os

SECRET_KEY = 'top-secret'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db1')
SQLALCHEMY_TRACK_MODIFICATIONS = False




