from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from datetime import datetime, timedelta
import re

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
jwt = JWTManager(app)
CORS(app)  # Allow all origins (recommended for deployment)

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://login:book@form-practice.gyvoj.mongodb.net/?retryWrites=true&w=majority&appName=form-practice")
client = MongoClient(MONGO_URI)
db = client.book_library
users_collection = db.users
reading_lists_collection = db.reading_lists

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    return len(password) >= 6

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'Flask API is running'}), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ('name', 'email', 'password')):
            return jsonify({'error': 'Missing required fields: name, email, password'}), 400

        name = data['name'].strip()
        email = data['email'].strip().lower()
        password = data['password']

        if not name:
            return jsonify({'error': 'Name cannot be empty'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'User with this email already exists'}), 409

        password_hash = generate_password_hash(password)
        user_doc = {
            'name': name,
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        result = users_collection.insert_one(user_doc)
        user_id = str(result.inserted_id)

        reading_list_doc = {
            'user_id': user_id,
            'reading_list': [],
            'read_books': [],
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        reading_lists_collection.insert_one(reading_list_doc)

        access_token = create_access_token(identity=user_id)

        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': {
                'id': user_id,
                'name': name,
                'email': email
            }
        }), 201
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ('email', 'password')):
            return jsonify({'error': 'Missing required fields: email, password'}), 400

        email = data['email'].strip().lower()
        password = data['password']

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        user = users_collection.find_one({'email': email})
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401

        user_id = str(user['_id'])
        access_token = create_access_token(identity=user_id)

        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user_id,
                'name': user['name'],
                'email': user['email']
            }
        }), 200
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
        }), 200
    except Exception as e:
        print(f"Get current user error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reading-list', methods=['GET'])
@jwt_required()
def get_reading_list():
    try:
        user_id = get_jwt_identity()
        reading_list = reading_lists_collection.find_one({'user_id': user_id})
        if not reading_list:
            reading_list_doc = {
                'user_id': user_id,
                'reading_list': [],
                'read_books': [],
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            reading_lists_collection.insert_one(reading_list_doc)
            return jsonify({'reading_list': [], 'read_books': []}), 200

        return jsonify({
            'reading_list': reading_list.get('reading_list', []),
            'read_books': reading_list.get('read_books', [])
        }), 200
    except Exception as e:
        print(f"Get reading list error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reading-list/add', methods=['POST'])
@jwt_required()
def add_to_reading_list():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data or 'book_id' not in data:
            return jsonify({'error': 'Missing book_id'}), 400

        book_id = data['book_id']
        reading_lists_collection.update_one(
            {'user_id': user_id},
            {
                '$addToSet': {'reading_list': book_id},
                '$set': {'updated_at': datetime.utcnow()}
            },
            upsert=True
        )

        return jsonify({'message': 'Book added to reading list'}), 200
    except Exception as e:
        print(f"Add to reading list error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reading-list/remove', methods=['POST'])
@jwt_required()
def remove_from_reading_list():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data or 'book_id' not in data:
            return jsonify({'error': 'Missing book_id'}), 400

        book_id = data['book_id']
        reading_lists_collection.update_one(
            {'user_id': user_id},
            {
                '$pull': {'reading_list': book_id},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )

        return jsonify({'message': 'Book removed from reading list'}), 200
    except Exception as e:
        print(f"Remove from reading list error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reading-list/mark-read', methods=['POST'])
@jwt_required()
def mark_as_read():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data or 'book_id' not in data:
            return jsonify({'error': 'Missing book_id'}), 400

        book_id = data['book_id']
        reading_lists_collection.update_one(
            {'user_id': user_id},
            {
                '$addToSet': {'read_books': book_id},
                '$pull': {'reading_list': book_id},
                '$set': {'updated_at': datetime.utcnow()}
            },
            upsert=True
        )

        return jsonify({'message': 'Book marked as read'}), 200
    except Exception as e:
        print(f"Mark as read error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reading-list/unmark-read', methods=['POST'])
@jwt_required()
def unmark_as_read():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data or 'book_id' not in data:
            return jsonify({'error': 'Missing book_id'}), 400

        book_id = data['book_id']
        reading_lists_collection.update_one(
            {'user_id': user_id},
            {
                '$pull': {'read_books': book_id},
                '$set': {'updated_at': datetime.utcnow()}
            }
        )

        return jsonify({'message': 'Book unmarked as read'}), 200
    except Exception as e:
        print(f"Unmark as read error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(422)
def handle_unprocessable_entity(e):
    return jsonify({'error': 'Invalid JWT token'}), 422

@app.errorhandler(401)
def handle_unauthorized(e):
    return jsonify({'error': 'Missing or invalid authorization token'}), 401

if __name__ == '__main__':
    print("Starting Flask API server...")
    print("MongoDB connection established")
    port = int(os.environ.get("PORT", 5000))  # For Render or cloud platform
    app.run(host='0.0.0.0', port=port, debug=False)  # Debug off in production
