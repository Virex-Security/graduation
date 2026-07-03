# Virex Security System

Virex is an AI-powered Web Application Firewall (WAF) and Security Information and Event Management (SIEM) dashboard. It intercepts incoming web traffic, performs deep inspection using a combination of static rules and machine learning, blocks malicious requests, and provides a comprehensive real-time dashboard for security analysts to monitor threats and manage incidents.

## Features

- **Traffic Interception & Proxying**: Acts as an application-layer firewall, intercepting traffic to inspect payloads and headers before forwarding to the target application.
- **Rule-Based WAF**: Detects common vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Command Injection, Server-Side Request Forgery (SSRF), and Cross-Site Request Forgery (CSRF).
- **Machine Learning Engine**: Utilizes a LightGBM classifier exported to ONNX Runtime and TF-IDF vectorization (via scikit-learn) to detect zero-day attacks and anomalies that bypass static regex rules.
- **Rate Limiting & Brute Force Protection**: Tracks request frequencies per IP address to automatically block distributed denial-of-service (DDoS) attempts and brute-force login attacks.
- **Real-Time Analytics Dashboard**: Visualizes traffic trends, attack distributions, top attackers, and ML performance metrics using Chart.js.
- **Incident Management**: Automatically groups related threat logs into actionable security incidents, allowing analysts to investigate, mitigate (e.g., block IP, rate limit), or close alerts.
- **Role-Based Access Control (RBAC)**: Supports Admin, User, Analyst, and Manager roles with JWT-based authentication.

## Architecture

The system operates on a dual-service architecture:

1. **API / WAF Engine (Port 5000)**: Serves as the primary inspection point.
   - **Step 1**: Incoming requests are checked against the rate limiter.
   - **Step 2**: The WAF engine matches the request path, method, headers, and body against known malicious patterns (stored in the database).
   - **Step 3**: The request is passed to the ML inference engine for anomaly scoring. If the confidence score exceeds the threshold, it is flagged.
   - **Step 4**: Detected threats are logged to the database. Malicious requests are blocked (returning a 403 Forbidden response), while clean requests are allowed through or forwarded to the proxy target.

2. **SIEM Dashboard (Port 8070)**: A web interface for administrators and analysts.
   - Pulls aggregated metrics, threat logs, and system health status from the PostgreSQL database.
   - Manages rules, blacklists, and incidents through internal API endpoints.

## Technology Stack

- **Backend**: Python 3, Flask, SQLAlchemy, JWT (PyJWT), Werkzeug
- **Machine Learning**: lightgbm, onnxruntime, scikit-learn (TfidfVectorizer), pandas, numpy
- **Frontend**: HTML5, Vanilla CSS, JavaScript, Chart.js
- **Database**: PostgreSQL (typically hosted via Supabase)
- **Infrastructure**: Designed for Docker containerization with separate services for the API and Dashboard.

## Project Structure

- `backend/app/api/`: Contains the core WAF engine, routing, and security middleware (`security.py`, `routes.py`).
- `backend/app/ml/`: Houses the machine learning modules, including feature extraction, inference engine, and background retraining loops (`inference.py`, `features.py`).
- `backend/app/dashboard/`: Contains the SIEM dashboard services, HTML rendering routes, and incident management logic (`routes.py`, `services.py`).
- `backend/app/auth/`: Manages JWT authentication, password hashing, roles, and OTP resets.
- `backend/app/database.py`: Centralized SQLAlchemy database connection and schema initialization.
- `backend/app/templates/`: Jinja2 HTML templates for the frontend dashboard.
- `backend/app/static/`: CSS and JavaScript files for frontend interactivity and charting.
- `backend/run_api.py`: Entrypoint for the WAF/API server.
- `backend/run_dashboard.py`: Entrypoint for the Dashboard server.
- `scripts/`: Utility scripts for generating realistic training data and testing components.

## Installation

### Prerequisites

- Python 3.10+
- PostgreSQL database
- Git

### Clone

```bash
git clone https://github.com/yourusername/virex-security.git
cd virex-security
```

### Install Dependencies

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r backend/requirements.txt
```

### Configure Environment

Create a `.env` file in the root directory with the following configuration:

```env
DATABASE_URL=postgresql://user:password@host:port/dbname
SECRET_KEY=your_secure_random_string
INTERNAL_API_SECRET=your_internal_communication_secret
SMTP_EMAIL=your_email@example.com
SMTP_PASSWORD=your_email_password
```

### Run Backend Services

Start the WAF API server:
```bash
python backend/run_api.py
```

Start the Dashboard server:
```bash
python backend/run_dashboard.py
```

Access the dashboard at `http://localhost:8070`.

## Configuration

The system's behavior can be tuned via the `backend/app/config.py` file and database settings. Important configurations include:
- `SECRET_KEY`: Used for JWT signing.
- `DATABASE_URL`: Connection string for PostgreSQL.
- Dashboard polling intervals and ML confidence thresholds are internally configured in the respective service files.

## API Overview

The internal API exposes several endpoints for dashboard functionality:

### Authentication
- `POST /api/auth/login`: Authenticate and receive a JWT.
- `POST /api/auth/signup`: Register a new user.
- `POST /api/request-reset-otp`: Request a password reset OTP.

### Security & Threats
- `GET /api/threats`: Retrieve paginated threat logs.
- `GET /api/incidents`: Fetch aggregated security incidents.
- `POST /api/incident/<id>/action`: Perform an action on an incident (e.g., Block IP, False Positive).

### Rules & Blacklist
- `GET /api/rules`: List active WAF rules.
- `GET /api/blocked-ips`: Retrieve the current IP blacklist.
- `POST /api/blocked-ips`: Manually add an IP to the blacklist.

### System & ML
- `GET /api/dashboard/data`: Fetch aggregate statistics, timeline data, and threat distribution for the dashboard.
- `GET /api/ml/stats`: Retrieve machine learning model accuracy, precision, and recall.

## Security Features

- **JWT Authentication**: Secure, stateless authentication for the dashboard.
- **IP Blacklisting**: Supports both manual blocking and automatic blocking triggered by brute-force or high-severity ML detections.
- **Fail-Closed Design**: If the WAF engine encounters an unhandled exception during inspection, it blocks the request with a 403 status to prevent bypasses.
- **Sanitization**: Database queries utilize SQLAlchemy parameterized statements to prevent SQL injection within the SIEM itself.

## Database

The PostgreSQL database relies on the following major tables:
- `users` & `roles`: RBAC management.
- `threat_logs`: Detailed records of every blocked or monitored request, including IP, payload snippet, and detection type.
- `system_stats`: High-performance counters for total requests and clean requests.
- `rate_limits`: Tracks IP request timestamps for sliding-window rate limiting.
- `blocked_ips`: The active blacklist.
- `rules`: Regex patterns used by the static WAF engine.
- `incidents` & `incident_actions`: Grouped threat logs and their corresponding mitigation audit trails.

## Logging and Monitoring

- **Application Logs**: Uses Python's standard `logging` module to output system status, initialization events, and severe errors to the console.
- **Audit Trail**: Security actions performed by analysts (e.g., blocking an IP, closing an incident) are logged directly to the database or internal JSON audit logs.

## Deployment

The repository is structured to support containerized deployment. While Dockerfiles and Nginx configurations are typically used to route external traffic through the WAF (Port 5000) before reaching the internal application network, the current repository relies on running the Flask applications directly. For production, deploy using Gunicorn or uWSGI behind a robust reverse proxy like Nginx.

## Current Limitations

- **In-Memory Caching**: Some state, such as temporary rate limit counters and recent incident groupings, are stored in memory, which may cause synchronization issues if deployed across multiple worker nodes without a centralized Redis cache.
- **Synchronous ML Inference**: The ML classification runs synchronously in the request path, which may introduce latency under extremely high traffic loads.

## Future Improvements

- **Asynchronous Processing**: Offload ML inference and database logging to background task queues (e.g., Celery) to reduce request latency.
- **Distributed Caching**: Implement Redis for rate limiting and session management to support multi-node scaling.
- **Customizable Rule Engine**: Provide a fully dynamic UI for creating and testing complex WAF rules beyond simple regex patterns.

## License

No license has been provided for this repository.
