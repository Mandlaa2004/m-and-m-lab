"""Load test for the M & M Lab SOC console.

Run with: locust -f tools/locustfile.py --host http://127.0.0.1:5000
Requires: pip install -r requirements-dev.txt
"""
from locust import HttpUser, between, task


class AnalystUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.client.get("/login")
        self.client.post(
            "/login", data={"username": "analyst", "password": "analyst123"})

    @task(3)
    def view_summary(self):
        self.client.get("/api/summary")

    @task(2)
    def view_events(self):
        self.client.get("/api/events?per_page=50")

    @task(2)
    def view_alerts(self):
        self.client.get("/api/alerts?per_page=50")

    @task(1)
    def view_incidents(self):
        self.client.get("/api/incidents")

    @task(1)
    def view_mitre_coverage(self):
        self.client.get("/api/mitre-coverage")
