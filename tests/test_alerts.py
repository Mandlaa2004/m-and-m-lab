from app import app


def test_alert_chain_and_incident_creation():
    with app.test_client() as client:
        client.get('/login')
        client.post(
            '/login', data={'username': 'analyst', 'password': 'analyst123'})
        with client.session_transaction() as session:
            token = session['csrf_token']
        event = client.post('/api/log-analyzer', json={'text': '\n'.join(
            ['Failed password for admin from 10.0.0.26'] * 5)}, headers={'X-CSRF-Token': token})
        incident = client.post(
            '/api/incidents', json={'title': 'Brute force review'}, headers={'X-CSRF-Token': token})
        alerts = client.get('/api/alerts')
    assert event.status_code == 200
    assert incident.status_code == 200
    assert alerts.status_code == 200
    assert alerts.json
