import os
import datetime
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from bson.objectid import ObjectId
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = "mongodb+srv://Bigdata:capstone66@cluster0.nplyvzs.mongodb.net/smartdb?retryWrites=true&w=majority&appName=Cluster0"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_secret_key")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your_google_client_id")
UPLOAD_FOLDER = 'uploads/videos'

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True)

users_collection = mongo.db.users

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Resource not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"message": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server error: {error}")
    return jsonify({"message": "Internal server error"}), 500

# Register
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not email or not password or not username:
            return jsonify({"message": "Username, email, and password are required"}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"message": "User already exists"}), 409

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        new_user = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "created_at": datetime.datetime.utcnow(),
            "name": username,
        }

        users_collection.insert_one(new_user)

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        app.logger.error(f"Error on /register: {e}")
        return jsonify({"message": "Failed to register user"}), 500

# Login
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = users_collection.find_one({"email": email})
        if not user or not bcrypt.check_password_hash(user["password"], password):
            return jsonify({"message": "Invalid email or password"}), 401

        access_token = create_access_token(identity=str(user["_id"]), expires_delta=datetime.timedelta(hours=1))

        user_data = {
            "id": str(user["_id"]),
            "username": user.get("username"),
            "email": user.get("email"),
            "created_at": user.get("created_at").strftime('%Y-%m-%d %H:%M:%S')
        }

        return jsonify({"access_token": access_token, "data": user_data, "message": "Login successful"}), 200
    except Exception as e:
        app.logger.error(f"Error on /login: {e}")
        return jsonify({"message": "Login failed"}), 500

# Login Basic Auth
@app.route("/login/basic", methods=["POST"])
def login_basic():
    try:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return jsonify({"message": "Missing credentials"}), 400

        identifier = auth.username
        password = auth.password

        user = users_collection.find_one({
            "$or": [{"email": identifier}, {"username": identifier}]
        })

        if not user or not user.get("password") or not bcrypt.check_password_hash(user["password"], password):
            return jsonify({"message": "Invalid credentials"}), 401

        token = create_access_token(identity=str(user["_id"]), expires_delta=datetime.timedelta(hours=1))
        return jsonify({"token": token, "user_name": user.get("name")}), 200
    except Exception as e:
        app.logger.error(f"Error on /login/basic: {e}")
        return jsonify({"message": "Basic login failed"}), 500

# Login Google
@app.route("/login/google", methods=["POST"])
def login_google():
    try:
        data = request.get_json()
        token = data.get("token")

        if not token:
            return jsonify({"message": "Missing Google token"}), 400

        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo["email"]
        name = idinfo.get("name")
        picture = idinfo.get("picture")

        user = users_collection.find_one({"email": email})
        if not user:
            result = users_collection.insert_one({
                "email": email,
                "name": name,
                "username": email.split("@")[0],
                "password": None,
                "picture": picture,
                "created_at": datetime.datetime.utcnow()
            })
            user_id = result.inserted_id
        else:
            user_id = user["_id"]

        jwt_token = create_access_token(identity=str(user_id), expires_delta=datetime.timedelta(hours=1))
        return jsonify({"token": jwt_token}), 200
    except ValueError:
        return jsonify({"message": "Invalid Google token"}), 400
    except Exception as e:
        app.logger.error(f"Error on /login/google: {e}")
        return jsonify({"message": "Google login failed"}), 500

# Profile - GET
@app.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({"message": "User not found"}), 404

        profile = {
            "user_id": str(user["_id"]),
            "email": user.get("email"),
            "name": user.get("name", ""),
            "phone": user.get("phone", ""),
            "username": user.get("username", ""),
            "gender": user.get("gender", ""),
            "picture": user.get("picture", "")
        }
        return jsonify(profile), 200
    except Exception as e:
        app.logger.error(f"Error on /profile GET: {e}")
        return jsonify({"message": "Failed to fetch profile"}), 500

# Profile - PUT
@app.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({"message": "No data provided"}), 400

        update_data = {}

        if "email" in data:
            email = data["email"].strip()
            if users_collection.find_one({"email": email, "_id": {"$ne": ObjectId(user_id)}}):
                return jsonify({"message": "Email already in use"}), 400
            update_data["email"] = email

        if "password" in data and data["password"]:
            update_data["password"] = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

        if "name" in data:
            update_data["name"] = data["name"].strip()

        if "phone" in data:
            update_data["phone"] = data["phone"].strip()

        if "username" in data:
            update_data["username"] = data["username"].strip()

        if "gender" in data:
            update_data["gender"] = data["gender"].strip()

        if not update_data:
            return jsonify({"message": "No valid data to update"}), 400

        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error on /profile PUT: {e}")
        return jsonify({"message": "Failed to update profile"}), 500

# Delete account
@app.route("/profile", methods=["DELETE"])
@jwt_required()
def delete_account():
    try:
        user_id = get_jwt_identity()
        users_collection.delete_one({"_id": ObjectId(user_id)})
        return jsonify({"message": "Account deleted"}), 200
    except Exception as e:
        app.logger.error(f"Error on /profile DELETE: {e}")
        return jsonify({"message": "Failed to delete account"}), 500

# Refresh token
@app.route("/refresh-token", methods=["POST"])
@jwt_required()
def refresh_token():
    try:
        user_id = get_jwt_identity()
        new_token = create_access_token(identity=user_id)
        return jsonify({"token": new_token}), 200
    except Exception as e:
        app.logger.error(f"Error on /refresh-token: {e}")
        return jsonify({"message": "Failed to refresh token"}), 500

# Upload Video
@app.route("/upload-video", methods=["POST"])
def upload_video():
    try:
        if 'video' not in request.files:
            return jsonify({'message': 'No video file provided'}), 400

        video = request.files['video']
        filename = secure_filename(video.filename)

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        video.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        return jsonify({'message': 'Video uploaded successfully', 'filename': filename}), 200
    except Exception as e:
        app.logger.error(f"Error on /upload-video: {e}")
        return jsonify({'message': 'Failed to upload video'}), 500

# Receive Detection Data
@app.route("/send-detection", methods=["POST"])
def receive_detection():
    try:
        data = request.json
        if not data:
            return jsonify({'message': 'No data received'}), 400

        app.logger.info(f"Received detection data: {data}")
        return jsonify({'message': 'Detection data received successfully'}), 200
    except Exception as e:
        app.logger.error(f"Error on /send-detection: {e}")
        return jsonify({'message': 'Failed to process detection data'}), 500

# Root
@app.route("/", methods=["GET"])
def hello():
    return jsonify({"msg": "API is ready"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
