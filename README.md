# M & M Lab

A local Flask security dashboard for monitoring and analyzing lab events. It includes a seeded SQLite event stream, local analyst login, severity analysis, event filtering, password-strength checks, IP classification, an audit trail, and CSV export.

The dashboard also includes a log-file analyzer for repeated failed logins, an offline rule-based intrusion detector, phishing URL heuristics, SHA-256 file integrity checks, a private-target TCP port scanner, and a lab vulnerability scan for commonly exposed services. These tools feed the same SIEM-style event and activity views.

## Architecture

The application follows `input -> parser/collector -> detection rule -> security event -> alert -> incident -> audit log`. SQLite stores users, events, alerts, incidents, rules, indicators, baselines, and audit records. See [ARCHITECTURE.md](ARCHITECTURE.md) for the data-flow diagram and table relationships.

The SOC upgrade adds incremental live-log monitoring, rule IDs and evidence, hourly metrics, local threat-intelligence indicators, automatic threat-intel matches, file tamper alerts, incident workflows, role-aware accounts, incident CSV reports, and a safe attack simulator. Start the simulator in another terminal, then poll `lab-events.log` from the dashboard:

```bash
python3 attack_simulator.py --kind failed --count 6 --interval 1
```

Demo roles are `admin` / `admin123`, `analyst` / `analyst123`, and `viewer` / `viewer123`. Admin-only account creation is available through `POST /api/users`; scanners are restricted to local lab targets.

## Run

```bash
python3 -m pip install -r requirements.txt
python3 app.py
```

Run the automated checks with `python3 -m pytest -q`. For a production-style local container, build with `docker build -t sentinel-lab .` and run with `docker run --rm -p 5000:5000 -e SECRET_KEY='replace-me' sentinel-lab`.

CI runs pytest, Python compilation, Ruff quality checks, and Trivy filesystem vulnerability scanning on every push and pull request.

Open <http://127.0.0.1:5000> and sign in with `analyst` / `analyst123`.

Set `SECRET_KEY` and the account password environment variables in the environment for anything beyond local demo use. The app is intentionally local-first: it does not send IP data to an external lookup service.

## Publication checklist

Before sharing the application outside your machine, copy `.env.example` to `.env`, generate a unique `SECRET_KEY`, set strong `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, and `VIEWER_PASSWORD` values, and keep `.env` private. Run the production container with `docker compose up --build`; it uses Gunicorn, a persistent data volume, production mode, and a health check. Put it behind HTTPS using a trusted reverse proxy or private tunnel. Do not expose Flask debug mode or the development server directly to the public internet.

Network and vulnerability scans are deliberately restricted to private, loopback, and link-local addresses. They check connectivity only and do not exploit services.

## Publish on Render (public internet)

Use Render for an always-on URL outside your local network. This repository includes `render.yaml` with service name `m-and-m-lab` and production defaults.

1. Push this project to GitHub.
2. In Render, create a new Blueprint and select your repository.
3. Confirm the service name is `m-and-m-lab` in the Blueprint preview.
4. Set secret environment values in Render: `SECRET_KEY`, `ADMIN_PASSWORD`, `ANALYST_PASSWORD`, and `VIEWER_PASSWORD`.
5. Deploy.

Render will provide a URL similar to `https://m-and-m-lab.onrender.com` if that subdomain is available. If it is already taken, use a close variant such as `m-and-m-lab-soc`.

`log_watcher.py` provides a continuously running background collector for local files. `ip-reputation` is intentionally offline by default and reports local registry status; an external provider can be added later behind an explicit API-key configuration.

## Portfolio demonstration

1. Start the dashboard with `python3 app.py`.
2. Start `python3 log_watcher.py lab-events.log` in a second terminal.
3. Generate six local failures with `python3 attack_simulator.py --kind failed --count 6 --interval 1`.
4. Open the dashboard and review the generated events, alerts, MITRE rule, and incident workflow.

The project security review is documented in [SECURITY.md](SECURITY.md). The test suite is split into authentication detection, IP safety, file integrity, log parsing, and alert-chain tests under `tests/`.

## Operator runbook

Run the dashboard in one terminal:

```bash
python3 app.py
```

In another terminal, start the local collector and simulator:

```bash
python3 log_watcher.py lab-events.log
python3 attack_simulator.py --kind failed --count 6 --interval 1
```

In the browser, open the live log monitor, inspect the generated `AUTH-001` alerts, click an event to review its evidence, open an investigation, and move it from `OPEN` to `INVESTIGATING` to `RESOLVED`. Use the assistant to ask for critical-event or investigation summaries, then export the event or incident CSV report.

## Release checks

```bash
python3 -m py_compile app.py attack_simulator.py log_watcher.py
python3 -m pytest -q
ruff check . --select F
```

CI repeats the tests and compilation, runs Ruff, and scans the repository with Trivy. Before sharing a deployment, configure `SECRET_KEY`, replace demo credentials, keep `.env` private, and use Gunicorn or Docker rather than Flask debug mode.
