import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import hashlib
import logging

# Deliberately vulnerable configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_123'  # Hardcoded secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'  # Insecure upload location
app.config['DEBUG'] = True  # Exposing debug information

# Intentionally verbose error logging
logging.basicConfig(level=logging.DEBUG)

db = SQLAlchemy(app)

# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Vulnerable database connection
def get_db_connection():
    return sqlite3.connect('vulnerable.db')

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query - SQL Injection possible
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
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
        
        # Weak password hashing (MD5)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # Vulnerable to SQL injection
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password_hash}', '{email}')"
        cursor.execute(query)
        conn.commit()
        
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
        'environment': os.environ.dict(),
        'python_version': sys.version,
        'app_config': app.config,
        'database_url': app.config['SQLALCHEMY_DATABASE_URI']
    }
    return jsonify(debug_info)

@app.route('/api/users')
def get_users():
    # Exposing all user data without authentication
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return jsonify(users)
