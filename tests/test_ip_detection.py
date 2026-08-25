from app import app


def test_public_scan_is_rejected():
    with app.test_client() as client:
        client.get('/login')
        client.post(
            '/login', data={'username': 'analyst', 'password': 'analyst123'})
        with client.session_transaction() as session:
            token = session['csrf_token']
        response = client.post(
            '/api/network-scan', json={'ip': '8.8.8.8', 'ports': '53'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 400
