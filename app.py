import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Deliberately vulnerable configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_123'  # Hardcoded secret key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')  # Using PostgreSQL
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'  # Insecure upload location
app.config['DEBUG'] = True  # Exposing debug information

# Intentionally verbose error logging
logging.basicConfig(level=logging.DEBUG)

db = SQLAlchemy(app)

# Import models after db initialization
from models import User

# Create tables
with app.app_context():
    db.create_all()

# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Still vulnerable to timing attacks
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Weak password hashing - deliberately vulnerable
        user = User(
            username=username,
            password=generate_password_hash(password),
            email=email
        )
        
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file:
            # Vulnerable file handling - no validation
            filename = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully')
    return render_template('upload.html')

@app.route('/debug')
def debug_info():
    # Exposing sensitive debug information
    debug_info = {
        'environment': dict(os.environ),
        'python_version': sys.version,
        'app_config': {k: str(v) for k, v in app.config.items()},
        'database_url': app.config['SQLALCHEMY_DATABASE_URI']
    }
    return jsonify(debug_info)

@app.route('/api/users')
def get_users():
    # Exposing all user data without authentication
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'password': user.password  # Deliberately exposing password hashes
    } for user in users])
