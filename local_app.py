import os, uuid
from datetime import timedelta
from argon2 import PasswordHasher
from bson.objectid import ObjectId
from flask import Flask, jsonify, render_template_string, request, send_from_directory, url_for
from flask_cors import CORS
from flask_jwt_extended import (JWTManager, create_access_token, get_jwt_identity, jwt_required)
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.config['MONGO_URI'] = 'mongodb://localhost:27017/21090116'
mongo = PyMongo(app)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

ph = PasswordHasher()
nama_aplikasi="Apkk_saya"
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='masteraldi2809@gmail.com',  # Ganti dengan email Anda
    MAIL_PASSWORD='xthezwlpdajgtlav',  # Ganti dengan password aplikasi yang dihasilkan
)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

# Definisikan model User dengan PyMongo
users = mongo.db.users

UPLOAD_FOLDER = "/home/student/21090116/crud/upload"# Ganti dengan path tempat menyimpan gambar
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

auth = HTTPBasicAuth()
@auth.verify_password
def verify_password(email, password):
    try:
        user = users.find_one({"email": email})
        if user and ph.verify(user["password"], password):
            return user
        return None
    except Exception as e:
        return None  # Ganti dengan respons None jika terjadi error

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return 'Haloo Satrio Aldi Selamat datang di aplikasi Flask saya!'

# Endpoint untuk mendapatkan semua pengguna
@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        all_users = users.find()
        user_list = []
        for user in all_users:
            user['_id'] = str(user['_id'])  # Konversi ObjectId ke string
            user_list.append(user)
        return jsonify(user_list), 200
    except Exception as e:
        return jsonify({"msg": str(e)}), 500

@app.post('/signup')
def signup():
    data = request.get_json()
    name = data["name"]
    email = data["email"]
    password = data["password"]

    if not email:
        return jsonify({"message": "Email harus diisi"}), 400

    if users.find_one({"email": email}):
        return jsonify({"message": "Email sudah terdaftar"}), 400

    hashed_password = ph.hash(password)
    new_user = {"name": name, "email": email, "password": hashed_password}
    users.insert_one(new_user)

    return jsonify({"message": "Berhasil mendaftar"}), 201

@app.post("/login_biasa")
def login_biasa():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email dan kata sandi diperlukan!"}), 400

    user = users.find_one({"email": email})

    if not user or not ph.verify(user["password"], password):
        return jsonify({"message": "Email atau kata sandi salah!"}), 400

    access_token = create_access_token(identity=str(user["_id"]))
    return jsonify({"token_access": access_token}), 200

@app.route("/login_basic_auth", methods=["POST"])
@auth.login_required
def login_basic_auth():
    try:
        user = auth.current_user()
        if user:
            access_token = create_access_token(identity=str(user["_id"]))
            return jsonify({"token_access": access_token}), 200
        return jsonify({"message": "Login failed"}), 401
    except Exception as e:
        print(str(e))
        return jsonify({"message": "Email atau kata sandi salah!"}), 400

@app.get("/myprofile")
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = users.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan."}), 404

    profile_picture_url = url_for('uploaded_file', filename=user.get("profile_picture", ""), _external=True)

    return jsonify({
        "id": str(user["_id"]),
        "email": user["email"],
        "name": user["name"],
        "profile_image_url": profile_picture_url
    }), 200


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/upload", methods=["POST"])
def upload():
    try:
        projectPath = "/home/student/21090116/crud"
        f = request.files['image']
        filename = f'{projectPath}/upload/{uuid.uuid4()}.jpg'
        f.save(filename)
        return jsonify({"msg": "gambar berhasil diupload"})
    except Exception as e:
        return jsonify({"msg": str(e)})
    
@app.put("/updateprofile")
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = users.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan."}), 404

    data = request.json
    new_name = data.get("name")
    new_email = data.get("email")

    if not new_name or not new_email:
        return jsonify({"message": "Nama dan email harus diisi."}), 400

    users.update_one({"_id": ObjectId(user_id)}, {
        "$set": {"name": new_name, "email": new_email}})

    return jsonify({"message": "Profil berhasil diperbarui."}), 200


@app.put("/changepassword")
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = users.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"message": "Pengguna tidak ditemukan."}), 404

    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"message": "Kata sandi lama dan baru harus diisi."}), 400

    if not ph.verify(user["password"], old_password):
        return jsonify({"message": "Kata sandi lama salah."}), 400

    hashed_new_password = ph.hash(new_password)
    users.update_one({"_id": ObjectId(user_id)}, {
        "$set": {"password": hashed_new_password}})

    return jsonify({"message": "Kata sandi berhasil diperbarui."}), 200

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return jsonify({"message": "Token telah kedaluwarsa"}), 400
    except BadSignature:
        return jsonify({"message": "Token tidak valid"}), 400

    if request.method == 'POST':
        new_password = request.form.get("new_password")

        if not new_password:
            return jsonify({"message": "Kata sandi baru harus diisi"}), 400

        hashed_password = ph.hash(new_password)
        
        users.update_one({"email": email}, {"$set": {"password": hashed_password}})
        
        return jsonify({"message": "Kata sandi berhasil direset"}), 200

    return '''
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Reset Password</title>
      </head>
      <body>
        <form action="/reset_password/{}" method="post">
          <label for="new_password">New Password:</label><br>
          <input type="password" id="new_password" name="new_password"><br>
          <input type="submit" value="Submit">
        </form> 
      </body>
    </html>
    '''.format(token)



@app.post("/forgotpassword")
def forgot_password():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"message": "Email harus diisi"}), 400
    
    user = users.find_one({"email": email})

    if not user:
        return jsonify({"message": "Email tidak ditemukan"}), 404

    token = s.dumps(email, salt='email-confirm')

    reset_password_url = url_for('reset_password', token=token, _external=True)
    email_body = render_template_string('''
        Hello {{ user["name"] }},
        
        Anda menerima email ini, karena kami menerima permintaan untuk mengatur ulang kata sandi akun Anda.
        
        Silakan klik tautan di bawah ini untuk mengatur ulang kata sandi Anda. Tautan ini akan kedaluwarsa dalam 1 jam.
        
        Reset your password: {{ reset_password_url }}
        
        Jika Anda tidak meminta pengaturan ulang kata sandi, abaikan email ini atau hubungi dukungan jika Anda memiliki pertanyaan.
        
        Untuk bantuan lebih lanjut, silakan hubungi tim dukungan kami di developer masteraldi2809@gmail.com.
        
        Salam Hangat,
        
        Mriki_Project
    ''', user=user,  reset_password_url=reset_password_url)

    msg = Message('Reset Kata Sandi Anda',
                  sender='masteraldi2809@gmail.com', recipients=[email])

    msg.body = email_body
    mail.send(msg)

    return jsonify({"message": "Email untuk mereset kata sandi telah dikirim."}), 200


@app.route('/updateprofilephoto', methods=['POST'])
@jwt_required()
def update_profile_photo():
    if 'profile_photo' not in request.files:
        return jsonify({"message": "Tidak ada file yang diunggah."}), 400

    file = request.files['profile_photo']

    if file.filename == '':
        return jsonify({"message": "Nama file kosong."}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        random_name = str(uuid.uuid4()) + ".jpg"
        print(os.path.join(app.config['UPLOAD_FOLDER'], random_name))
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], random_name))

        user_id = get_jwt_identity()
        user = users.find_one({"_id": ObjectId(user_id)})

        if not user:
            return jsonify({"message": "Pengguna tidak ditemukan."}), 404

        users.update_one({"_id": ObjectId(user_id)}, {
            "$set": {"profile_picture": random_name}})

        return jsonify({"message": "Foto profil berhasil diperbarui."}), 200

    return jsonify({"message": "File tidak valid."}), 400


@app.route('/delete_all_users', methods=['DELETE'])
def delete_all_users():
    users.delete_many({})
    return jsonify({"message": "Semua pengguna berhasil dihapus."}), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=21116)
