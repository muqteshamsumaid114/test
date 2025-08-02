# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
# IMPORTANT: Change this secret key to a random, secure key for production
app.secret_key = os.urandom(24)

# Admin credentials loaded from the .env file
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Global dictionary to track failed login attempts for brute-force protection
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300 # 5 minutes in seconds

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Creates the necessary database tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create users table with a username and a hashed password.
    # Storing plain text passwords is a huge security risk.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
    ''')
    # Create a table to log failed login attempts for threat detection
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

# Run this once to set up the database
create_tables()

def hash_password(password):
    """Hashes a password using SHA-256 for secure storage."""
    # Add a unique salt to make rainbow table attacks harder.
    # In a real app, you would use a more robust library like bcrypt.
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt.hex() + ':' + key.hex()

def verify_password(stored_password, provided_password):
    """Verifies a provided password against a stored hashed password."""
    salt_hex, key_hex = stored_password.split(':')
    salt = bytes.fromhex(salt_hex)
    key = bytes.fromhex(key_hex)
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000
    )
    return new_key == key

def is_locked_out(username):
    """
    Checks if a user has exceeded the max failed login attempts
    within the lockout time window.
    """
    if username in FAILED_ATTEMPTS:
        last_attempt_time = FAILED_ATTEMPTS[username]['timestamp']
        if time.time() - last_attempt_time < LOCKOUT_TIME and \
           FAILED_ATTEMPTS[username]['count'] >= MAX_ATTEMPTS:
            return True
        # Reset the counter if the lockout time has passed
        if time.time() - last_attempt_time >= LOCKOUT_TIME:
            del FAILED_ATTEMPTS[username]
    return False

def log_failed_attempt(username):
    """Logs a failed login attempt to the database."""
    conn = get_db_connection()
    conn.execute("INSERT INTO failed_logins (username, timestamp) VALUES (?, ?)", (username, int(time.time())))
    conn.commit()
    conn.close()

# Main application routes
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if is_locked_out(username):
            flash('Account is locked. Please try again in 5 minutes.', 'error')
            log_failed_attempt(username)
            return redirect(url_for('login'))

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Prevent SQL Injection with a parameterized query
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            session['is_admin'] = False
            
            if username in FAILED_ATTEMPTS:
                del FAILED_ATTEMPTS[username]
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            
            if username not in FAILED_ATTEMPTS:
                FAILED_ATTEMPTS[username] = {'count': 0, 'timestamp': time.time()}
            
            FAILED_ATTEMPTS[username]['count'] += 1
            FAILED_ATTEMPTS[username]['timestamp'] = time.time()
            log_failed_attempt(username)
            
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration with password hashing."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Prevent SQL Injection with a parameterized query
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/index')
def index():
    """User dashboard - protected route."""
    if not session.get('logged_in'):
        flash('You must be logged in to view this page.', 'error')
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

# Admin routes
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['is_admin'] = True
            session['username'] = username
            flash('Admin logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'error')
            return redirect(url_for('admin_login'))
            
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin dashboard - protected route."""
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('You must be an admin to view this page.', 'error')
        return redirect(url_for('admin_login'))
        
    conn = get_db_connection()
    # Fetch all failed login attempts
    failed_attempts_db = conn.execute("SELECT * FROM failed_logins ORDER BY timestamp DESC").fetchall()
    conn.close()

    threat_logs = []
    for log in failed_attempts_db:
        log_dict = dict(log)
        log_dict['timestamp_str'] = time.ctime(log_dict['timestamp'])
        threat_logs.append(log_dict)

    return render_template('admin_dashboard.html', threat_logs=threat_logs)

@app.route('/logout')
def logout():
    """Logs the user/admin out and clears the session."""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
