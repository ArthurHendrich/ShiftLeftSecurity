import os
import sys
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
import yaml
from yaml import load, Loader  # Vulnerable to deserialization attacks
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import requests
from cryptography.hazmat.primitives import hashes
import paramiko
import jwt
import urllib3
urllib3.disable_warnings()  # Disabling SSL warnings - vulnerable
import subprocess
import pickle
import xml.etree.ElementTree as ET
import base64
import hashlib
import json

from database import db
from models import User, Vulnerability

from scanner import VulnerabilityScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_123'  # Hardcoded secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'  # Using SQLite for development
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'  # Insecure upload location
app.config['DEBUG'] = True  

logging.basicConfig(level=logging.DEBUG)

db.init_app(app)

with app.app_context():
    db.create_all()

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Ensure database tables are created
with app.app_context():
    db.create_all()

from scanner import VulnerabilityScanner
scanner = VulnerabilityScanner(app)

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
    vulnerabilities = Vulnerability.query.all()
    return render_template('dashboard.html', vulnerabilities=vulnerabilities)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file and file.filename:
            # Vulnerable file handling - no validation
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            flash('File uploaded successfully')
    return render_template('upload.html', files=os.listdir(app.config['UPLOAD_FOLDER']) if os.path.exists(app.config['UPLOAD_FOLDER']) else [])

@app.route('/yaml-parser', methods=['POST'])
def yaml_parser():
    # Vulnerable to YAML deserialization
    yaml_data = request.data.decode('utf-8')
    return jsonify(yaml.load(yaml_data, Loader=Loader))

@app.route('/remote-exec', methods=['POST'])
def remote_exec():
    # Vulnerable SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('localhost', username='root', password='root')
    return jsonify({'status': 'connected'})

@app.route('/fetch-url')
def fetch_url():
    # Using vulnerable requests version
    url = request.args.get('url')
    response = requests.get(url, verify=False)
    return response.text

@app.route('/generate-token')
def generate_token():
    # Using vulnerable JWT version with none algorithm
    payload = {'user': 'admin'}
    return jwt.encode(payload, None, algorithm='none')

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

@app.route('/api/users', methods=['GET'])
def get_users():
    # Exposing all user data without authentication
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'password': user.password,  # Deliberately exposing password hashes
        'api_key': getattr(user, 'api_key', None)  # Safely get api_key if exists
    } for user in users])

@app.route('/security-dashboard')
def security_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).all()
    stats = scanner.get_stats()
    return render_template('security_dashboard.html', vulnerabilities=vulnerabilities, stats=stats)

@app.route('/start-scan', methods=['POST'])
def start_scan():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    scanner.scan_directory()
    return jsonify({'status': 'started'})

@app.route('/vulnerability-stream')
def vulnerability_stream():
    def generate():
        last_check = datetime.utcnow()
        while True:
            with app.app_context():
                # Get new vulnerabilities since last check
                new_vulns = Vulnerability.query.filter(Vulnerability.discovered_at > last_check).all()
                if new_vulns:
                    stats = scanner.get_stats()
                    for vuln in new_vulns:
                        data = {
                            'stats': stats,
                            'new_vulnerability': {
                                'type': vuln.type,
                                'severity': vuln.severity,
                                'description': vuln.description,
                                'location': vuln.location,
                                'status': vuln.status,
                                'discovered_at': vuln.discovered_at.isoformat()
                            }
                        }
                        yield f"data: {jsonify(data).get_data(as_text=True)}\n\n"
                last_check = datetime.utcnow()
            time.sleep(2)  # Check every 2 seconds
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/exec_code', methods=['POST'])
def exec_code():
    # Remote Code Execution vulnerability
    code = request.form.get('code')
    try:
        result = eval(code)  # Dangerous eval execution
        return jsonify({'result': str(result)})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/fetch', methods=['GET'])
def fetch_url_api():
    # SSRF vulnerability
    url = request.args.get('url')
    response = requests.get(url, verify=False)
    return response.text

@app.route('/api/weak_hash', methods=['POST'])
def weak_hash():
    # Weak hashing implementation
    data = request.form.get('data')
    return jsonify({
        'md5': hashlib.md5(data.encode()).hexdigest(),
        'sha1': hashlib.sha1(data.encode()).hexdigest()
    })

@app.route('/api/redirect', methods=['GET'])
def redirect_url():
    # Open redirect vulnerability
    url = request.args.get('url')
    return redirect(url)

@app.route('/api/file_read', methods=['GET'])
def read_file():
    # Path traversal vulnerability
    filename = request.args.get('filename')
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return str(e)

@app.route('/api/save_data', methods=['POST'])
def save_data():
    # NoSQL Injection vulnerability example
    data = request.get_json()
    query = json.loads(data.get('query', '{}'))
    # Simulating NoSQL query execution
    return jsonify({'status': 'saved', 'query': query})

@app.route('/api/health', methods=['GET'])
def health_check():
    # Information disclosure in health check
    import platform
    return jsonify({
        'status': 'up',
        'python_version': sys.version,
        'platform': platform.platform(),
        'environment': dict(os.environ),
        'dependencies': {
            'Flask': Flask.__version__,
            'SQLAlchemy': SQLAlchemy.__version__
        }
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
