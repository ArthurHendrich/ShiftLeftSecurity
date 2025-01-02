from models import User, Vulnerability
from werkzeug.security import generate_password_hash

def test_user_creation(test_app, test_db):
    user = User(
        username='testuser',
        password=generate_password_hash('password123'),
        email='test@example.com'
    )
    test_db.session.add(user)
    test_db.session.commit()
    
    assert user.id is not None
    assert user.username == 'testuser'
    assert user.email == 'test@example.com'

def test_vulnerability_creation(test_app, test_db):
    vuln = Vulnerability(
        type='XSS',
        severity='High',
        description='Test vulnerability',
        location='test_file.py:10'
    )
    test_db.session.add(vuln)
    test_db.session.commit()
    
    assert vuln.id is not None
    assert vuln.type == 'XSS'
    assert vuln.severity == 'High'
    assert vuln.status == 'open'
