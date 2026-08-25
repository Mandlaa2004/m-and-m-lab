from app import app


def test_malformed_log_is_safe():
    with app.test_client() as client:
        client.get('/login')
        client.post(
            '/login', data={'username': 'analyst', 'password': 'analyst123'})
        with client.session_transaction() as session:
            token = session['csrf_token']
        response = client.post('/api/log-analyzer', json={
                               'text': '\x00not a normal log\n{broken'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 200
    assert response.json['lines'] == 2
