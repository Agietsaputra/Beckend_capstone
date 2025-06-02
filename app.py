import os
from datetime import datetime, timedelta
import logging
import random
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
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message
import string
from flask import send_from_directory



load_dotenv()

MONGO_URI = "mongodb+srv://Bigdata:capstone66@cluster0.nplyvzs.mongodb.net/smartdb?retryWrites=true&w=majority&appName=Cluster0"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_secret_key")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your_google_client_id")

# Folder untuk video dan profile pictures
UPLOAD_FOLDER_VIDEOS = 'uploads/videos'
UPLOAD_FOLDER_PROFILE_PICS = 'uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

# Set folder upload
app.config["UPLOAD_FOLDER_VIDEOS"] = UPLOAD_FOLDER_VIDEOS
app.config["UPLOAD_FOLDER_PROFILE_PICS"] = UPLOAD_FOLDER_PROFILE_PICS
app.config["ALLOWED_EXTENSIONS"] = ALLOWED_EXTENSIONS
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == "True"
app.config['MAIL_USE_SSL'] = os.getenv("MAIL_USE_SSL") == "True"
app.config['MAIL_USERNAME'] = os.getenv("EMAIL_ADDRESS")
app.config['MAIL_PASSWORD'] = os.getenv("EMAIL_PASSWORD")

mail = Mail(app)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True)

users_collection = mongo.db.users


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

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    msg = Message('Kode OTP Verifikasi Akun',
                  sender=os.getenv("EMAIL_ADDRESS"),
                  recipients=[email])
    msg.body = f"Kode OTP kamu adalah: {otp}. Jangan berikan kepada siapa pun. Berlaku selama 10 menit."
    mail.send(msg)

# ================= REGISTER =================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Semua field wajib diisi'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Email sudah digunakan'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    otp = generate_otp()
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)

    user_data = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'is_verified': False,
        'otp': otp,
        'otp_expiry': otp_expiry,
        'created_at': datetime.utcnow()
    }

    users_collection.insert_one(user_data)
    send_otp_email(email, otp)

    return jsonify({'message': 'OTP telah dikirim ke email kamu'}), 200

# ================= LOGIN OTP - REQUEST OTP =================
@app.route("/request-otp", methods=["POST"])
def request_otp():
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"message": "Email is required"}), 400

        # Cek apakah email sudah digunakan untuk akun aktif
        if users_collection.find_one({"email": email}):
            return jsonify({"message": "Email already registered"}), 400

        otp = str(random.randint(100000, 999999))
        expiration = datetime.utcnow() + timedelta(minutes=10)

        # Simpan OTP sementara ke pending_otps
        mongo.db.pending_otps.update_one(
            {"email": email},
            {"$set": {"otp_code": otp, "otp_expiration": expiration}},
            upsert=True
        )

        # Simulasi kirim email
        print(f"[SIMULATED EMAIL] OTP for {email} is {otp}")

        return jsonify({"message": "OTP sent to email"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to send OTP: {str(e)}"}), 500


# ================= LOGIN OTP - VERIFY OTP =================
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_input = data.get('otp')

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    if user.get('is_verified'):
        return jsonify({'message': 'Akun sudah terverifikasi'}), 400

    if datetime.utcnow() > user.get('otp_expiry', datetime.utcnow()):
        return jsonify({'message': 'OTP telah kedaluwarsa, silakan daftar ulang'}), 400

    if str(user.get('otp')) != str(otp_input):
        return jsonify({'message': 'Kode OTP salah'}), 401

    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'is_verified': True}, '$unset': {'otp': "", 'otp_expiry': ""}}
    )

    return jsonify({'message': 'Verifikasi berhasil. Silakan login.'}), 200


# ================= LOGIN PASSWORD =================
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"message": "Invalid email or password"}), 401

        # cek password hashed
        if not bcrypt.check_password_hash(user["password"], password):
            return jsonify({"message": "Invalid email or password"}), 401

        access_token = create_access_token(identity=str(user["_id"]), expires_delta=timedelta(hours=1))

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
    
# ================= LOGIN GOOGLE =================
@app.route("/login/google", methods=["POST"])
def login_google():
    try:
        data = request.get_json()
        token = data.get("token")

        if not token:
            return jsonify({"message": "Missing Google token"}), 400

        try:
            idinfo = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                GOOGLE_CLIENT_ID
            )
        except ValueError:
            return jsonify({"message": "Invalid Google token"}), 400

        email = idinfo.get("email")
        name = idinfo.get("name", email.split("@")[0])
        picture = idinfo.get("picture", "")

        if not email:
            return jsonify({"message": "Email not found in token"}), 400

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

        jwt_token = create_access_token(
            identity=str(user_id),
            expires_delta=datetime.timedelta(hours=1)
        )

        return jsonify({
            "token": jwt_token,
            "user": {
                "email": email,
                "name": name,
                "picture": picture
            }
        }), 200

    except Exception as e:
        logging.exception("Unexpected error during Google login:")
        return jsonify({"message": "Google login failed", "error": str(e)}), 500

# ================= PROFILE =================
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

@app.route("/refresh-token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    try:
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, expires_delta=datetime.timedelta(hours=1))
        return jsonify({"access_token": new_token}), 200
    except Exception as e:
        return jsonify({"message": "Token refresh failed"}), 500

# ================= UPLOAD VIDEO =================
@app.route("/upload-video", methods=["POST"])
@jwt_required()
def upload_video():
    try:
        if "video" not in request.files:
            return jsonify({"message": "No video file provided"}), 400

        video_file = request.files["video"]
        if video_file.filename == "":
            return jsonify({"message": "No selected file"}), 400

        filename = secure_filename(video_file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Buat folder upload jika belum ada
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        video_file.save(save_path)

        return jsonify({"message": "Video uploaded successfully", "filename": filename}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to upload video: {str(e)}"}), 500

@app.route("/profile/picture", methods=["POST"])
@jwt_required()
def upload_profile_picture():
    try:
        user_id = get_jwt_identity()

        if "picture" not in request.files:
            return jsonify({"message": "No file part"}), 400

        file = request.files["picture"]

        if file.filename == "":
            return jsonify({"message": "No selected file"}), 400

        # Validasi ekstensi file
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

        if not allowed_file(file.filename):
            return jsonify({"message": "File type not allowed"}), 400

        filename = secure_filename(file.filename)
        # Beri nama file unik supaya tidak bentrok, misalnya dengan user_id dan timestamp
        ext = filename.rsplit('.', 1)[1].lower()
        filename = f"user_{user_id}_{int(datetime.utcnow().timestamp())}.{ext}"

        upload_folder = 'uploads/profile_pictures'
        os.makedirs(upload_folder, exist_ok=True)
        save_path = os.path.join(upload_folder, filename)
        file.save(save_path)

        # Simpan path/url file ke database user
        picture_url = f"/{upload_folder}/{filename}"
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"picture": picture_url}})

        return jsonify({"message": "Foto profil berhasil diunggah", "picture_url": picture_url}), 200

    except Exception as e:
        app.logger.error(f"Error on /profile/picture: {e}")
        return jsonify({"message": "Gagal mengunggah foto profil"}), 500


if __name__ == "__main__":
    app.run(debug=True)
