from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Expense, ExpenseCategory
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400

    if len(data['username']) < 3 or len(data['password']) < 6:
        return jsonify({'message': 'Username must be at least 3 characters and password at least 6 characters'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    user.set_token(access_token) 
    db.session.commit()

    return jsonify({'access_token': access_token}), 200

@app.route('/check_token', methods=['GET'])
@jwt_required()
def check_token():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or user.is_token_expired():
        return jsonify({'message': 'Token is expired'}), 401

    return jsonify({'message': 'Token is valid'}), 200

@app.route('/expenses', methods=['POST'])
@jwt_required()
def add_expense():
    user_id = get_jwt_identity()
    data = request.get_json()

    try:
        if 'amount' not in data or type(data['amount']) not in [int, float] or data['amount'] <= 0:
            return jsonify({'message': 'Invalid amount'}), 400

        if 'category' not in data or data['category'].upper() not in ExpenseCategory.__members__:
            return jsonify({'message': 'Invalid category'}), 400

        date_str = data.get('date', datetime.now().strftime('%Y-%m-%d'))
        date = datetime.strptime(date_str, '%Y-%m-%d')

        new_expense = Expense(
            amount=data['amount'],
            category=ExpenseCategory[data['category'].upper()],
            description=data.get('description', ''),
            date=date,
            user_id=user_id
        )

        db.session.add(new_expense)
        db.session.commit()

        return jsonify({'message': 'Expense added successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 400

@app.route('/expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    user_id = get_jwt_identity()
    filter_type = request.args.get('filter', 'all')
    query = Expense.query.filter_by(user_id=user_id)
    now = datetime.now()

    try:
        if filter_type == 'week':
            query = query.filter(Expense.date >= now - timedelta(days=7))
        elif filter_type == 'month':
            start_of_month = now.replace(day=1)  
            query = query.filter(Expense.date >= start_of_month)
        elif filter_type == 'three_months':
            three_months_ago = now - timedelta(days=90)
            query = query.filter(Expense.date >= three_months_ago)
        elif filter_type == 'custom':
            start_date = datetime.strptime(request.args.get('start_date'), '%Y-%m-%d')
            end_date = datetime.strptime(request.args.get('end_date'), '%Y-%m-%d')
            query = query.filter(Expense.date.between(start_date, end_date))

        expenses = query.order_by(Expense.date.desc()).all()

        return jsonify([{
            'id': expense.id,
            'amount': expense.amount,
            'category': expense.category.value,
            'description': expense.description,
            'date': expense.date.strftime('%Y-%m-%d')
        } for expense in expenses]), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 400

@app.route('/expenses/<int:expense_id>', methods=['PUT'])
@jwt_required()
def update_expense(expense_id):
    user_id = get_jwt_identity()
    expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()

    if not expense:
        return jsonify({'message': 'Expense not found'}), 404

    data = request.get_json()

    try:
        if 'amount' in data:
            if type(data['amount']) not in [int, float] or data['amount'] <= 0:
                return jsonify({'message': 'Invalid amount'}), 400
            expense.amount = data['amount']
        if 'category' in data:
            if data['category'].upper() not in ExpenseCategory.__members__:
                return jsonify({'message': 'Invalid category'}), 400
            expense.category = ExpenseCategory[data['category'].upper()]
        if 'description' in data:
            expense.description = data['description']
        if 'date' in data:
            expense.date = datetime.strptime(data['date'], '%Y-%m-%d')

        db.session.commit()
        return jsonify({'message': 'Expense updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 400

@app.route('/expenses/<int:expense_id>', methods=['DELETE'])
@jwt_required()
def delete_expense(expense_id):
    user_id = get_jwt_identity()
    expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()

    if not expense:
        return jsonify({'message': 'Expense not found'}), 404

    try:
        db.session.delete(expense)
        db.session.commit()
        return jsonify({'message': 'Expense deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)