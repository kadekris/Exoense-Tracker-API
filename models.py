from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from enum import Enum

db = SQLAlchemy()

class ExpenseCategory(Enum):
    GROCERIES = "Groceries"
    LEISURE = "Leisure"
    ELECTRONICS = "Electronics"
    UTILITIES = "Utilities"
    CLOTHING = "Clothing"
    HEALTH = "Health"
    OTHERS = "Others"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(200), nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    expenses = db.relationship('Expense', backref='user', lazy=True)

    def set_token(self, token, expiry_hours=1):
        self.token = token
        self.token_expiry = datetime.now() + timedelta(hours=expiry_hours) 

    def is_token_expired(self):
        now_local = datetime.now() 
        return now_local > self.token_expiry if self.token_expiry else True

class Expense(db.Model):
    __tablename__ = 'expenses'
    
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.Enum(ExpenseCategory), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)