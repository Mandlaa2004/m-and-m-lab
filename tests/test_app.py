from datetime import datetime, timedelta, timezone

import pytest

import app as app_module


@pytest.fixture()
def isolated_app(tmp_path, monkeypatch):
    database = tmp_path / "test.db"
    monkeypatch.setattr(app_module, "DATABASE", database)
    monkeypatch.setattr(app_module, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(app_module, "MUTATION_REQUESTS", {})
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
    intelligence = client.post(
        '/api/ip-info', json={'ip': '185.220.101.14'}, headers={'X-CSRF-Token': token})
    assert intelligence.json['threat_score'] >= 78
    assert intelligence.json['activity']
    incident = client.post(
        '/api/incidents', json={'title': 'Workflow test'}, headers={'X-CSRF-Token': token}).json[0]
    response = client.patch('/api/incidents', json={
                            'id': incident['id'], 'status': 'INVESTIGATING', 'response_stage': 'CONTAIN'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 200
    assert response.json[0]['response_stage'] == 'CONTAIN'


def test_operational_workflows_store_evidence_and_saved_views(isolated_app):
    client, token = logged_in_client(isolated_app)
    incident = client.post(
        '/api/incidents', json={'title': 'Evidence case'}, headers={'X-CSRF-Token': token}).json[0]
    evidence = client.post(f"/api/incidents/{incident['id']}/evidence", json={
        'evidence_type': 'LOG', 'content': 'Failed login from a correlated source'}, headers={'X-CSRF-Token': token})
    assert evidence.status_code == 200
    assert evidence.json[0]['evidence_type'] == 'LOG'
    saved = client.post('/api/saved-searches', json={
        'name': 'Critical events', 'severity': 'CRITICAL'}, headers={'X-CSRF-Token': token})
    assert saved.status_code == 200
    assert saved.json[0]['name'] == 'Critical events'
    assert len(client.get('/api/mitre-coverage').json) == 7
    assert len(client.get('/api/playbooks').json) == 4
    assert client.get('/export/audit.csv').status_code == 200


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


def test_admin_can_backup_and_prune_events(isolated_app):
    client = isolated_app.test_client()
    client.get('/login')
    with client.session_transaction() as session:
        token = session['csrf_token']
    client.post('/login', data={'username': 'admin',
                'password': 'admin123', 'csrf_token': token})
    with client.session_transaction() as session:
        token = session['csrf_token']
    with client.application.app_context():
        app_module.record_event(
            'Old resolved event', '10.0.0.60', 'LOW', 'Stale evidence')
        with app_module.get_db() as db:
            db.execute("UPDATE events SET status = 'Resolved', timestamp = ? WHERE source_ip = ?",
                       ((datetime.now(timezone.utc) - timedelta(days=200)
                         ).isoformat(), '10.0.0.60'))
    backup = client.post('/api/maintenance/backup',
                         headers={'X-CSRF-Token': token})
    assert backup.status_code == 201
    assert client.get('/api/maintenance/backups').json[0]['name'] == backup.json['name']
    prune = client.post('/api/maintenance/prune', json={
                        'retention_days': 30}, headers={'X-CSRF-Token': token})
    assert prune.status_code == 200
    assert prune.json['deleted_events'] == 1


def test_mutation_rate_limit_returns_429(isolated_app):
    client, token = logged_in_client(isolated_app)
    responses = [client.post('/api/incidents', json={'title': f'Case {i}'},
                             headers={'X-CSRF-Token': token}) for i in range(35)]
    assert any(response.status_code == 429 for response in responses)


def test_events_and_alerts_are_paginated(isolated_app):
    client, token = logged_in_client(isolated_app)
    with client.application.app_context():
        for i in range(5):
            app_module.record_event(
                'Log detection', f'10.0.0.{i}', 'HIGH', 'Paginated evidence')
    response = client.get('/api/events?per_page=2')
    assert len(response.json) == 2
    assert int(response.headers['X-Total-Count']) >= 5
    alerts_response = client.get('/api/alerts?per_page=2')
    assert len(alerts_response.json) <= 2
    assert 'X-Total-Count' in alerts_response.headers


def test_critical_event_dispatches_external_webhook(isolated_app, monkeypatch):
    monkeypatch.setenv('NOTIFY_WEBHOOK_URL', 'https://example.invalid/webhook')
    calls = []
    monkeypatch.setattr(app_module, 'urlopen',
                        lambda request, timeout=3: calls.append(request))
    with isolated_app.test_client() as client:
        client.get('/login')
        with client.session_transaction() as session:
            token = session['csrf_token']
        client.post('/login', data={'username': 'analyst',
                    'password': 'analyst123', 'csrf_token': token})
        with client.application.app_context():
            app_module.record_event(
                'Malware signature', '10.0.0.70', 'CRITICAL', 'Webhook test evidence')
    assert calls


def test_revoking_sessions_signs_out_current_session(isolated_app):
    client, token = logged_in_client(isolated_app)
    assert client.get('/api/summary').status_code == 200
    revoke = client.delete('/api/account/sessions',
                           headers={'X-CSRF-Token': token})
    assert revoke.status_code == 200
    assert client.get('/api/summary').status_code == 302


def test_totp_setup_verify_and_login_challenge(isolated_app):
    client = isolated_app.test_client()
    client.get('/login')
    with client.session_transaction() as session:
        token = session['csrf_token']
    client.post('/login', data={'username': 'admin',
                'password': 'admin123', 'csrf_token': token})
    with client.session_transaction() as session:
        token = session['csrf_token']
    setup = client.post('/api/account/totp/setup',
                        headers={'X-CSRF-Token': token})
    assert setup.status_code == 200
    secret = setup.json['secret']
    valid_code = app_module._totp_code_at(
        secret, int(datetime.now(timezone.utc).timestamp() // 30))
    verify = client.post('/api/account/totp/verify', json={
                         'code': valid_code}, headers={'X-CSRF-Token': token})
    assert verify.status_code == 200
    client.get('/logout')
    client.get('/login')
    with client.session_transaction() as session:
        token = session['csrf_token']
    missing_code = client.post('/login', data={'username': 'admin',
                               'password': 'admin123', 'csrf_token': token})
    assert missing_code.status_code == 200
    assert b'authenticator' in missing_code.data.lower()
    with client.session_transaction() as session:
        token = session['csrf_token']
    valid_code = app_module._totp_code_at(
        secret, int(datetime.now(timezone.utc).timestamp() // 30))
    success = client.post('/login', data={'username': 'admin', 'password': 'admin123',
                          'totp_code': valid_code, 'csrf_token': token})
    assert success.status_code == 302


def test_audit_filters_and_export(isolated_app):
    client, token = logged_in_client(isolated_app)
    with client.application.app_context():
        app_module.record_event(
            'Log detection', '10.0.0.80', 'HIGH', 'Audit filter evidence')
    filtered = client.get('/api/audit?action=Log%20detection')
    assert filtered.status_code == 200
    export = client.get('/export/activity.csv')
    assert export.status_code == 200
    assert export.mimetype == 'text/csv'


def test_teams_can_be_created_and_scope_assets(isolated_app):
    client, token = logged_in_client(isolated_app)
    with client.session_transaction() as session:
        session['role'] = 'Admin'
    create = client.post(
        '/api/teams', json={'name': 'Blue Team'}, headers={'X-CSRF-Token': token})
    assert create.status_code == 200
    assert any(team['name'] == 'Blue Team' for team in create.json)
    asset = client.post('/api/assets', json={
                        'name': 'Team asset', 'ip_address': '10.0.0.90', 'team': 'Blue Team'}, headers={'X-CSRF-Token': token})
    assert asset.status_code == 201
    scoped = client.get('/api/assets?team=Blue%20Team')
    assert scoped.json[0]['team'] == 'Blue Team'


def test_threat_feed_sync_imports_indicators(isolated_app, monkeypatch):
    client, token = logged_in_client(isolated_app)
    with client.session_transaction() as session:
        session['role'] = 'Admin'

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"1.2.3.4\n# comment\nnot-an-ip\n5.6.7.8\n"

    monkeypatch.setattr(app_module, 'urlopen', lambda request,
                        timeout=5: FakeResponse())
    response = client.post('/api/threat-intel/sync', json={
                           'url': 'https://example.invalid/feed.txt'}, headers={'X-CSRF-Token': token})
    assert response.status_code == 200
    assert response.json['added'] == 2


def test_mitre_navigator_export_returns_layer(isolated_app):
    client, _ = logged_in_client(isolated_app)
    response = client.get('/api/mitre-coverage/navigator')
    assert response.status_code == 200
    assert response.json['domain'] == 'enterprise-attack'
    assert len(response.json['techniques']) == len(app_module.MITRE_TECHNIQUES)
