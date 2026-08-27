import pytest

import app as app_module


@pytest.fixture()
def isolated_app(tmp_path, monkeypatch):
    database = tmp_path / "test.db"
    monkeypatch.setattr(app_module, "DATABASE", database)
    app_module.initialize_database()
    app_module.app.config.update(TESTING=True)
    return app_module.app


def logged_in_client(isolated_app):
    client = isolated_app.test_client()
    client.get('/login')
    with client.session_transaction() as session:
        token = session['csrf_token']
    response = client.post(
        '/login', data={'username': 'analyst', 'password': 'analyst123', 'csrf_token': token})
    assert response.status_code == 302
    return client, token


def test_login_and_protected_route(isolated_app):
    client, _ = logged_in_client(isolated_app)
    assert client.get('/api/summary').status_code == 200


def test_scanner_rejects_public_target(isolated_app):
    client, token = logged_in_client(isolated_app)
    response = client.post(
        '/api/network-scan', json={'ip': '8.8.8.8', 'ports': '53'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 400


def test_ids_returns_mitre_rule(isolated_app):
    client, token = logged_in_client(isolated_app)
    response = client.post(
        '/api/ids-analyze', json={'text': 'nmap port scan detected'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 200
    assert response.json['matches'][0]['mitre'] == 'T1046'


def test_viewer_cannot_manage_users(isolated_app):
    client = isolated_app.test_client()
    client.get('/login')
    with client.session_transaction() as session:
        token = session['csrf_token']
    assert client.post('/login', data={'username': 'viewer',
                       'password': 'viewer123', 'csrf_token': token}).status_code == 302
    assert client.get('/api/users').status_code == 403


def test_security_headers_are_present(isolated_app):
    response = isolated_app.test_client().get('/login')
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert 'default-src' in response.headers['Content-Security-Policy']


def test_mutation_without_csrf_is_rejected(isolated_app):
    client, _ = logged_in_client(isolated_app)
    response = client.post('/api/incidents', json={'title': 'Blocked request'})
    assert response.status_code == 403


def test_asset_lifecycle_and_validation(isolated_app):
    client, token = logged_in_client(isolated_app)
    response = client.post(
        '/api/assets', json={'name': 'Lab server', 'ip_address': '10.0.0.20'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 201
    assert client.get('/api/assets').json[0]['name'] == 'Lab server'
    invalid = client.post(
        '/api/assets', json={'name': 'Bad asset', 'ip_address': 'not-an-ip'}, headers={'X-CSRF-Token': token})
    assert invalid.status_code == 400


def test_alert_triage_and_incident_timeline(isolated_app):
    client, token = logged_in_client(isolated_app)
    with client.application.app_context():
        app_module.record_event(
            'Log detection', '10.0.0.21', 'HIGH', 'Evidence')
    alert_id = client.get('/api/alerts').json[0]['id']
    triage = client.patch(
        f'/api/alerts/{alert_id}', json={'status': 'ACKNOWLEDGED'}, headers={'X-CSRF-Token': token})
    assert triage.status_code == 200
    incident = client.post(
        '/api/incidents', json={'title': 'Timeline test'}, headers={'X-CSRF-Token': token})
    incident_id = incident.json[0]['id']
    timeline = client.get(f'/api/incidents/{incident_id}/timeline')
    assert timeline.status_code == 200
    assert timeline.json[0]['action'] == 'Investigation opened'


def test_event_detail_supports_alert_investigation(isolated_app):
    client, _ = logged_in_client(isolated_app)
    with client.application.app_context():
        app_module.record_event(
            'Log detection', '10.0.0.45', 'HIGH', 'Inspection evidence')
    event_id = client.get('/api/events?q=Inspection evidence').json[0]['id']
    response = client.get(f'/api/events/{event_id}')
    assert response.status_code == 200
    assert response.json['message'] == 'Inspection evidence'
    assert client.get('/api/events/999999').status_code == 404


def test_threat_intelligence_summary_and_response_workflow(isolated_app):
    client, token = logged_in_client(isolated_app)
    with client.application.app_context():
        app_module.record_event(
            'Threat signal', '185.220.101.14', 'CRITICAL', 'Known hostile activity')
    summary = client.get('/api/summary').json
    assert len(summary['response_stages']) == 5
    assert summary['threats'][0]['score'] >= 78
    assert summary['progress']['level'] >= 1
    intelligence = client.post('/api/ip-info', json={'ip': '185.220.101.14'}, headers={'X-CSRF-Token': token})
    assert intelligence.json['threat_score'] >= 78
    assert intelligence.json['activity']
    incident = client.post('/api/incidents', json={'title': 'Workflow test'}, headers={'X-CSRF-Token': token}).json[0]
    response = client.patch('/api/incidents', json={'id': incident['id'], 'status': 'INVESTIGATING', 'response_stage': 'CONTAIN'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 200
    assert response.json[0]['response_stage'] == 'CONTAIN'


def test_collector_rejects_external_path_and_health_is_public(isolated_app):
    client, token = logged_in_client(isolated_app)
    response = client.post('/api/collectors', json={
                           'name': 'External', 'path': '/tmp/system.log'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 400
    assert client.get('/api/health').json['status'] == 'healthy'


def test_high_severity_event_creates_notification(isolated_app):
    client, token = logged_in_client(isolated_app)
    with client.application.app_context():
        app_module.record_event(
            'Log detection', '10.0.0.44', 'CRITICAL', 'Malware evidence')
    notifications = client.get('/api/notifications')
    assert notifications.status_code == 200
    assert any(item['severity'] == 'CRITICAL' and item['title'] == 'Critical security event'
               for item in notifications.json['items'])
    read = client.post('/api/notifications/read-all',
                       headers={'X-CSRF-Token': token})
    assert read.status_code == 200
    assert client.get('/api/notifications').json['unread'] == 0


def test_login_attempts_create_notifications(isolated_app):
    client = isolated_app.test_client()
    client.get('/login')
    with client.session_transaction() as session:
        token = session['csrf_token']
    failed = client.post(
        '/login', data={'username': 'unknown', 'password': 'wrong', 'csrf_token': token})
    assert failed.status_code == 200
    with client.session_transaction() as session:
        token = session['csrf_token']
    assert client.post('/login', data={'username': 'analyst',
                       'password': 'analyst123', 'csrf_token': token}).status_code == 302
    notifications = client.get('/api/notifications').json['items']
    assert any(item['kind'] == 'authentication' and item['severity']
               == 'HIGH' for item in notifications)
    assert any(item['kind'] == 'authentication' and item['title']
               == 'User signed in' for item in notifications)
