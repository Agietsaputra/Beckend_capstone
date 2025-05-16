import os
import datetime
import jwt
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from werkzeug.utils import secure_filename

# Konfigurasi
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
SECRET_KEY = os.getenv("SECRET_KEY", "your_jwt_secret")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your_google_client_id")
UPLOAD_FOLDER = 'uploads/videos'

# Inisialisasi
app = Flask(__name__)
bcrypt = Bcrypt(app)
client = MongoClient(MONGO_URI)
db = client["smartstrech"]
users_collection = db["users"]

CORS(app, supports_credentials=True)

# Helper Functions
def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.check_password_hash(hashed, password)

def generate_token(user_id):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["user_id"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Register
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"message": "Name, email, and password are required"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}), 400

    if users_collection.find_one({"name": name}):
        return jsonify({"message": "Name already exists"}), 400

    hashed_pw = hash_password(password)
    result = users_collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_pw,
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({
        "message": "User registered successfully",
        "user_id": str(result.inserted_id)
    }), 201

# Login Manual
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    identifier = data.get("identifier")
    password = data.get("password")

    if not identifier or not password:
        return jsonify({"message": "Identifier and password required"}), 400

    user = users_collection.find_one({
        "$or": [
            {"email": identifier},
            {"name": identifier}
        ]
    })

    if not user or not user.get("password") or not check_password(password, user["password"]):
        return jsonify({"message": "Invalid credentials"}), 401

    token = generate_token(user["_id"])
    return jsonify({
        "token": token,
        "user_name": user.get("name"),
        "email": user.get("email")
    }), 200

# Login Basic Auth
@app.route("/login/basic", methods=["POST"])
def login_basic():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({"message": "Missing credentials"}), 400

    identifier = auth.username
    password = auth.password

    user = users_collection.find_one({
        "$or": [
            {"email": identifier},
            {"name": identifier}
        ]
    })

    if not user or not user.get("password") or not check_password(password, user["password"]):
        return jsonify({"message": "Invalid credentials"}), 401

    token = generate_token(user["_id"])
    return jsonify({"token": token, "user_name": user.get("name")}), 200

# Login Google
@app.route("/login/google", methods=["POST"])
def login_google():
    data = request.get_json()
    token = data.get("token")

    if not token:
        return jsonify({"message": "Missing Google token"}), 400

    try:
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        email = idinfo["email"]
        name = idinfo.get("name")
        picture = idinfo.get("picture")

        user = users_collection.find_one({"email": email})
        if not user:
            result = users_collection.insert_one({
                "email": email,
                "password": None,
                "name": name,
                "picture": picture,
                "created_at": datetime.datetime.utcnow()
            })
            user_id = result.inserted_id
        else:
            user_id = user["_id"]

        jwt_token = generate_token(user_id)
        return jsonify({"token": jwt_token}), 200

    except ValueError:
        return jsonify({"message": "Invalid Google token"}), 400

# Get Profile
@app.route("/profile", methods=["GET"])
def get_profile():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"message": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({"message": "Token is invalid or expired"}), 401

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "user_id": str(user["_id"]),
        "email": user["email"],
        "name": user.get("name"),
        "picture": user.get("picture")
    }), 200

# Update Profile
@app.route("/profile", methods=["PUT"])
def update_profile():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"message": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({"message": "Invalid or expired token"}), 401

    data = request.get_json()
    new_email = data.get("email")
    new_password = data.get("password")
    new_name = data.get("name")
    new_picture = data.get("picture")

    update_data = {}

    if new_email and new_email.strip() != "":
        if users_collection.find_one({"email": new_email, "_id": {"$ne": ObjectId(user_id)}}):
            return jsonify({"message": "Email already in use"}), 400
        update_data["email"] = new_email.strip()

    if new_password and new_password.strip() != "":
        update_data["password"] = hash_password(new_password.strip())

    if new_name and new_name.strip() != "":
        update_data["name"] = new_name.strip()

    if new_picture and new_picture.strip() != "":
        update_data["picture"] = new_picture.strip()

    if not update_data:
        return jsonify({"message": "No data to update"}), 400

    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )

    return jsonify({"message": "Profile updated successfully"}), 200

# Update Nama
@app.route("/profile/name", methods=["PUT"])
def update_name():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"message": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({"message": "Invalid or expired token"}), 401

    data = request.get_json()
    new_name = data.get("name")

    if not new_name:
        return jsonify({"message": "Name is required"}), 400

    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"name": new_name}}
    )

    return jsonify({"message": "Name updated successfully"}), 200

# Delete Account
@app.route("/profile", methods=["DELETE"])
def delete_account():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"message": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({"message": "Invalid or expired token"}), 401

    users_collection.delete_one({"_id": ObjectId(user_id)})
    return jsonify({"message": "Account deleted"}), 200

# Upload Video
@app.route("/upload-video", methods=["POST"])
def upload_video():
    if 'video' not in request.files:
        return jsonify({'message': 'No video file provided'}), 400

    video = request.files['video']
    filename = secure_filename(video.filename)

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    video.save(save_path)

    return jsonify({'message': 'Video uploaded successfully', 'filename': filename}), 200

# Send Detection
@app.route("/send-detection", methods=["POST"])
def receive_detection():
    data = request.json

    if not data:
        return jsonify({'message': 'No data received'}), 400

    print("Received detection data:", data)
    # Kamu bisa simpan ke MongoDB jika dibutuhkan
    return jsonify({'message': 'Detection data received successfully'}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)