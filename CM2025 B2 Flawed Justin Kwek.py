import sqlite3


def authenticate_user(username, password):
    # FLAW 1: SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Dangerous: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()

    # FLAW 2: Hardcoded credentials
    if username == "admin" and password == "admin123":
        return True

    conn.close()
    return user is not None


# Usage
print(authenticate_user("admin", "' OR '1'='1"))  # Bypasses authentication!
print(authenticate_user("admin", "admin123"))  # Hardcoded credential