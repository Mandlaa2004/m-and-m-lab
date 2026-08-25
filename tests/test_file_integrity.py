from pathlib import Path

from app import app


def test_file_hash_is_stable_for_project_file():
    with app.test_client() as client:
        client.get('/login')
        client.post(
            '/login', data={'username': 'analyst', 'password': 'analyst123'})
        with client.session_transaction() as session:
            token = session['csrf_token']
        response = client.post(
            '/api/file-integrity', json={'path': 'app.py'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 200
    assert len(response.json['sha256']) == 64
    assert Path('app.py').exists()
