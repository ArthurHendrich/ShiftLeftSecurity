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

from database import db
from models import User, Vulnerability

from scanner import VulnerabilityScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_123'  # Hardcoded secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'  # Using SQLite for development
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'  # Insecure upload location
app.config['DEBUG'] = True  # Exposing debug information

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
    return render_template('upload.html')

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
