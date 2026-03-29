# Database helper functions to avoid circular imports
# Move all user-related DB functions here

import sqlite3
from roles import Role

def get_user_by_username(username):
    # Example implementation, adjust as needed
    conn = sqlite3.connect('db/virex.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user['role'] = user.get('role', Role.USER)
        return user
    return None

def insert_user(username, password_hash, role=Role.USER):
    conn = sqlite3.connect('db/virex.db')
    cur = conn.cursor()
    cur.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password_hash, role))
    conn.commit()
    conn.close()

def update_user(username, **kwargs):
    # Whitelist allowed fields to prevent SQL injection in keys
    allowed_fields = {'password', 'email', 'department', 'full_name', 'phone', 'role'}

    update_kwargs = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not update_kwargs:
        return

    conn = sqlite3.connect('db/virex.db')
    cur = conn.cursor()
    fields = []
    values = []
    for k, v in update_kwargs.items():
        fields.append(f'{k} = ?')
        values.append(v)
    values.append(username)
    sql = f'UPDATE users SET {", ".join(fields)} WHERE username = ?'
    cur.execute(sql, values)
    conn.commit()
    conn.close()

def delete_user(username):
    conn = sqlite3.connect('db/virex.db')
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
