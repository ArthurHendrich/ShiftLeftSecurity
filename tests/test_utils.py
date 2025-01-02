from utils import hash_password, allowed_file

def test_hash_password():
    password = "test123"
    hashed = hash_password(password)
    assert len(hashed) == 32
    assert isinstance(hashed, str)

def test_allowed_file():
    assert allowed_file("test.txt") == True
    assert allowed_file("test.exe") == True
