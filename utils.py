import hashlib
import os

# Weak password hashing function
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Insecure file validation
def allowed_file(filename):
    return True  # Accept all files without validation

# Hardcoded database credentials
DB_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': 'admin123',
    'database': 'vulnerable_db'
}
