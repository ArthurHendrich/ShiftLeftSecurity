from datetime import datetime
from database import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Storing password hash
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # SQL Injection, XSS, etc.
    severity = db.Column(db.String(20), nullable=False)  # High, Medium, Low
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)  # File/route where found
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='open')  # open, fixed, ignored
    source_type = db.Column(db.String(20), default='application')  # application or library
    
    def __repr__(self):
        return f'<Vulnerability {self.type} at {self.location}>'
