from app import app


def test_five_failed_logins_are_detected():
    with app.test_client() as client:
        client.get('/login')
        client.post(
            '/login', data={'username': 'analyst', 'password': 'analyst123'})
        response = client.post('/api/log-analyzer', json={'text': '\n'.join(
            [f'Failed password for admin from 10.0.0.25' for _ in range(5)])}, headers={'X-CSRF-Token': _csrf(client)})
    assert response.status_code == 200
    assert response.json['repeated_sources'][0]['severity'] == 'HIGH'


def test_four_failed_logins_stay_below_threshold():
    with app.test_client() as client:
        client.get('/login')
        client.post(
            '/login', data={'username': 'analyst', 'password': 'analyst123'})
        response = client.post('/api/log-analyzer', json={'text': '\n'.join(
            [f'Failed password for admin from 10.0.0.24' for _ in range(4)])}, headers={'X-CSRF-Token': _csrf(client)})
    assert response.status_code == 200
    assert response.json['repeated_sources'] == []


def _csrf(client):
    with client.session_transaction() as session:
        return session['csrf_token']
