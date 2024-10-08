import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'clave_secreta_predeterminada'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///sensores.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
