from flask import Flask, jsonify, request, session, render_template, g, send_from_directory, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, unset_jwt_cookies
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_bcrypt import Bcrypt
from datetime import timedelta
from functools import wraps
from flask_cors import CORS
import os

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'sistem'
project_directory = os.path.abspath(os.path.dirname(__file__))
upload_folder = os.path.join(project_directory, 'static', 'image')
app.config['UPLOAD_FOLDER'] = upload_folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/sistem'
app.config['SECRET_KEY'] = 'bukan rahasia'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = b'asahdjhwquoyo192382qo'
app.config['JWT_SECRET_KEY'] = 'qwdu92y17dqsu81'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

ALLOWED_EXTENSIONS = {'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define the 'user_roles' class before 'User' class
class UserRoles(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary='user_roles', 
                            primaryjoin='User.id == UserRoles.user_id',
                            secondaryjoin='Role.id == UserRoles.role_id',
                            backref=db.backref('users', lazy='dynamic'))
    fs_uniquifier = db.Column(db.String(64), unique=True)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

jwt = JWTManager(app)
mysql = MySQL()
mysql.init_app(app)

# allow CORS biar api yang dibuat bisa dipake website lain
CORS(app)

@app.route('/sitemap.xml')
def sitemap():
    # Logika untuk menghasilkan sitemap.xml
    return send_from_directory(app.static_folder, 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    # Logika untuk menghasilkan robots.txt
    response = """User-agent: *
Disallow: /private/
Disallow: /cgi-bin/
Disallow: /images/
Disallow: /pages/thankyou.html
"""
    return response, 200, {'Content-Type': 'text/plain'}

# Fungsi untuk menangani kesalahan 404
@app.errorhandler(404)
def page_not_found(error):
    # Cek apakah klien meminta JSON
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        # Jika klien meminta JSON, kirim respons dalam format JSON
        response = jsonify({'error': 'Not found'})
        response.status_code = 404
        return response
    # Jika tidak, kirim respons dalam format HTML
    return render_template('404.html'), 404

# Route untuk halaman yang tidak ada
@app.route('/invalid')
def invalid():
    # Menggunakan abort untuk memicu kesalahan 404
    abort(404)

@app.route('/masuk')
def masuk():
    return render_template('admin/admin.html')

# Endpoint untuk membuat token
@app.route('/proses_masuk', methods=['POST'])
def proses_masuk():
    username = request.json['username']
    password = request.json['password']

    # Verifikasi kredensial pengguna
    user = user_datastore.find_user(username=username)
    if not user:
        return "username salah"
    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        session['jwt_token'] = access_token
        session['username'] = username
        return jsonify(access_token=access_token)
    else:
        return "password salah"

# Endpoint yang memerlukan autentikasi
@app.route('/keluar')
def keluar():
    response = jsonify({'message': 'Logout berhasil'})
    unset_jwt_cookies(response)
    session.pop('jwt_token', None)
    session.pop('username', None)
    flash('Sukses Logout')
    return redirect(url_for('masuk'))

@jwt.expired_token_loader
def expired_token_callback():
    return redirect(url_for('masuk'))

@app.route('/bikin_akun', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return jsonify({"msg": "Username and password are required"}), 400
        
        # Check if the username already exists
        if user_datastore.find_user(username=username):
            return jsonify({"msg": "Username already exists"}), 400

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user
        user = user_datastore.create_user(username=username, password=hashed_password, active=True)
        db.session.commit()
        # Logout
        response = jsonify({'message': 'Logout berhasil'})
        unset_jwt_cookies(response)
        session.pop('jwt_token', None)
        session.pop('username', None)
        flash('Sukses Logout')
        return redirect(url_for('masuk', msg='Registration Successful'))

    return render_template('admin/register.html')

if __name__ == '__main__':
    app.run()
