import sqlite3
import hashlib
import os


def get_db_connection():
    """Create database connection and ensure table exists."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Create table if not exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (username TEXT PRIMARY KEY, password_hash BLOB, salt BLOB)''')
    conn.commit()
    return conn


def secure_authenticate_user(username, password):
    """Authenticate user using parameterised queries and secure password hashing."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Parameterised query - safe from SQL injection
    query = "SELECT password_hash, salt FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return False

    stored_hash, salt = result

    # Hash the provided password with the stored salt using PBKDF2
    test_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    return test_hash == stored_hash


def create_user(username, password):
    """Create a new user with securely hashed password."""
    # Generate a random salt
    salt = os.urandom(32)

    # Hash password with salt using PBKDF2
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if user already exists
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print(f"User '{username}' already exists. Skipping creation.")
        conn.close()
        return False

    cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                   (username, password_hash, salt))
    conn.commit()
    conn.close()
    return True


def delete_user(username):
    """Delete a user from the database (for testing purposes)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def list_users():
    """List all users in the database (for testing purposes)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()
    conn.close()
    return [user[0] for user in users]


# Example usage and testing
if __name__ == "__main__":
    print("=" * 50)
    print("SECURE AUTHENTICATION SYSTEM - TESTING")
    print("=" * 50)

    # Clean up any existing test user
    print("\n1. Cleaning up existing users...")
    delete_user("admin")

    # List current users
    print("2. Current users:", list_users())

    # Create test user
    print("\n3. Creating user 'admin'...")
    create_user("admin", "SecurePass123!")

    # List users after creation
    print("4. Users after creation:", list_users())

    # Test authentication
    print("\n5. Testing Authentication:")
    print("   Valid credentials (admin/SecurePass123!):",
          secure_authenticate_user("admin", "SecurePass123!"))
    print("   SQL injection attempt (admin/' OR '1'='1):",
          secure_authenticate_user("admin", "' OR '1'='1"))
    print("   Wrong password (admin/wrong):",
          secure_authenticate_user("admin", "wrong"))
    print("   Non-existent user (nonexistent/password):",
          secure_authenticate_user("nonexistent", "password"))

    print("\n" + "=" * 50)
    print("TESTING COMPLETE")
    print("=" * 50)