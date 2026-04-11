from app.database import db_cursor
from datetime import datetime

# ── BLACKLIST TABLE HELPERS ──

def get_all_blacklist():
    with db_cursor() as cur:
        cur.execute("SELECT * FROM blacklist ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]

def insert_blacklist_entry(entry):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO blacklist (type, value, reason, status, added_by, date_added)
                   VALUES (?, ?, ?, ?, ?, ?)""",
            (
                entry['type'],
                entry['value'],
                entry['reason'],
                entry.get('status', 'active'),
                entry.get('added_by'),
                entry.get('date_added', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
        )
        return cur.lastrowid

def update_blacklist_entry(entry_id, data):
    # Strict allowlist — only these column names may appear in the SET clause
    ALLOWED_COLUMNS = frozenset({'reason', 'status', 'updated_by', 'date_updated'})

    # Build params dict with only validated column names
    params = {k: data[k] for k in ALLOWED_COLUMNS if k in data}
    if not params:
        return False

    # Column names come only from ALLOWED_COLUMNS — values bound as named parameters
    set_clause = ", ".join(f"{col} = :{col}" for col in params)
    params['entry_id'] = entry_id  # bind WHERE value as a named parameter too

    with db_cursor() as cur:
        cur.execute(
            f"UPDATE blacklist SET {set_clause} WHERE id = :entry_id",  # noqa: S608
            params
        )
        return cur.rowcount > 0


def delete_blacklist_entry(entry_id):
    with db_cursor() as cur:
        cur.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
        return cur.rowcount > 0

def get_blacklist_entry(entry_id):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM blacklist WHERE id = ?", (entry_id,))
        row = cur.fetchone()
        return dict(row) if row else None
