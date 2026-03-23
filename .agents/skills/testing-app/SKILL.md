# Testing the Graduation (Virex Security) App

## Quick Start

1. Activate the virtual environment: `source .venv/bin/activate`
2. Start the API server: `python run_api.py` (runs on port 5000)
3. Start the Dashboard server: `python run_dashboard.py` (runs on port 8070)
4. Both servers use Flask debug mode with auto-reload enabled

## Devin Secrets Needed

- `VIREX_ADMIN_USERNAME` — Admin login username
- `VIREX_ADMIN_PASSWORD` — Admin login password
- `VIREX_USER_USERNAME` — Regular user login username
- `VIREX_USER_PASSWORD` — Regular user login password

Credentials can be found in `data/users.json` (passwords are hashed). Default credentials are set up during project initialization.

## Key URLs

- Dashboard: `http://localhost:8070/dashboard`
- Login: `http://localhost:8070/login`
- API Health: `http://localhost:5000/api/health`
- User Manager (admin-only): `http://localhost:8070/user-manager`
- Blacklist (admin-only): `http://localhost:8070/blacklist`
- Settings (admin-only): `http://localhost:8070/settings`

## Admin-Only Features

The sidebar shows these links only when logged in as admin:
- User Manager (`/user-manager`)
- Blacklist (`/blacklist`)
- Reset Stats (button in sidebar)

## User Manager UI

The user table has 3 action buttons per row:
1. **Eye icon** — View user details (opens modal with user info)
2. **Ban/Check icon** — Toggle user active/inactive status
3. **Trash icon** — Delete user (shows Arabic confirmation dialog)

Note: There is NO role-change button in the UI. The `changeRole` API endpoint exists but is not wired to any UI element. Role changes can only be tested via API.

## Blacklist UI

- "Add to Blacklist" button opens a modal with Type (IP/Domain/User Agent), Value, Reason, and Active checkbox
- Each entry has Edit, Pause, and Delete action buttons
- Confirmation dialogs appear in Arabic

## Data Storage

All data is stored in JSON files under `data/`:
- `data/users.json` — User accounts
- `data/blacklist.json` — Blacklist entries
- `data/siem_audit.json` — Audit logs

## Known Quirks

- **Connection status flicker**: After the dashboard server auto-reloads (e.g., due to code changes detected by the file watcher), the sidebar may briefly show "Disconnected" until the next API health check succeeds. Refreshing the page usually resolves this.
- **Arabic UI elements**: Confirmation dialogs (delete user, delete blacklist entry, reset stats) display text in Arabic. The green checkmark button confirms, the red X cancels.
- **Port conflicts**: If ports 5000/8070 are occupied from previous runs, use `fuser -k 5000/tcp` and `fuser -k 8070/tcp` to free them. Note that `lsof` may not be available on the system.
- **Auto-reload**: Both servers run with `debug=True` and will auto-restart when Python files change. This can cause brief "Disconnected" states.
- **No lint tooling**: The project has no configured linter or type checker. Run `python -m pytest tests/ -q` for unit tests (41 tests).
