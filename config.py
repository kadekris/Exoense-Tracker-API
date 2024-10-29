from datetime import timedelta
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = '5FUygFtL7fZlOeJ3j5QmNk_AdJ-LpR9tBpZzU7_7vYo'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///expense_tracker.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = '5FUygFtL7fZlOeJ3j5QmNk_AdJ-LpR9tBpZzU7_7vYo'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)