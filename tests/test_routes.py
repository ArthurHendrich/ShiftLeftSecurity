import json

def test_index_route(test_client):
    response = test_client.get('/')
    assert response.status_code == 200


def test_register_route(test_client):
    register_data = {
        'username': 'newuser',
        'password': 'newpass123',
        'email': 'new@example.com'
    }
    response = test_client.post('/register', data=register_data)
    assert response.status_code == 302
