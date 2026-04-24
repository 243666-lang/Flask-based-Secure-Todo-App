import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo
import os
from datetime import timedelta
import time

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(32)

# CSRF Protection
csrf = CSRFProtect(app)

# Secure session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15)
)

# Track login attempts
login_attempts = {}

# ==================== DATABASE SETUP ====================

def init_database():
    conn = sqlite3.connect("users.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task TEXT NOT NULL,
            completed BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    conn.close()

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

init_database()

# ==================== FORMS ====================

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20),
        Regexp(r'^[A-Za-z0-9_]+$', message='Username: letters, numbers, underscore only')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
               message='Password needs: Uppercase, Lowercase, Number, Special (@$!%*#?&)')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class TodoForm(FlaskForm):
    task = StringField('Task', validators=[DataRequired(), Length(min=1, max=200)])

# ==================== SECURITY HEADERS ====================

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net"
    return response

# ==================== SECURITY LOGGING ====================

def log_security_event(event_type, username, ip_address, details=""):
    with open("security.log", "a") as log:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{timestamp}] {event_type} | User: {username} | IP: {ip_address} | {details}\n")

# ==================== ROUTES ====================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        hashed_password = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            log_security_event("REGISTRATION_SUCCESS", username, request.remote_addr, "New user created")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('error.html', msg="Username already exists")
        finally:
            db.close()
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    ip_address = request.remote_addr
    
    # Rate limiting
    if ip_address in login_attempts:
        attempts, last_time = login_attempts[ip_address]
        if attempts >= 5 and time.time() - last_time < 60:
            return render_template('error.html', msg="Too many attempts. Wait 60 seconds.")
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user'] = username
            session['user_id'] = user['id']
            session.permanent = True
            login_attempts[ip_address] = (0, time.time())
            log_security_event("LOGIN_SUCCESS", username, ip_address, "Successful login")
            return redirect(url_for('dashboard'))
        else:
            if ip_address in login_attempts:
                attempts, _ = login_attempts[ip_address]
                login_attempts[ip_address] = (attempts + 1, time.time())
            else:
                login_attempts[ip_address] = (1, time.time())
            log_security_event("LOGIN_FAILED", username, ip_address, "Invalid credentials")
            return render_template('error.html', msg="Invalid username or password")
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user_id = session['user_id']
    stats = db.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) as completed
        FROM todos WHERE user_id = ?
    """, (user_id,)).fetchone()
    db.close()
    
    return render_template('dashboard.html', 
                          user=session['user'], 
                          total_tasks=stats['total'] or 0,
                          completed_tasks=stats['completed'] or 0)

@app.route('/todos', methods=['GET', 'POST'])
def manage_todos():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    form = TodoForm()
    db = get_db()
    user_id = session['user_id']
    
    if form.validate_on_submit():
        task = form.task.data.strip()
        db.execute("INSERT INTO todos (user_id, task) VALUES (?, ?)", (user_id, task))
        db.commit()
        log_security_event("TASK_ADDED", session['user'], request.remote_addr, f"Task: {task[:50]}")
        return redirect(url_for('manage_todos'))
    
    tasks = db.execute("SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    db.close()
    
    return render_template('todos.html', form=form, tasks=tasks)

@app.route('/complete/<int:task_id>')
def complete_task(task_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user_id = session['user_id']
    task = db.execute("SELECT completed FROM todos WHERE id = ? AND user_id = ?", (task_id, user_id)).fetchone()
    
    if task:
        new_status = 0 if task['completed'] else 1
        db.execute("UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?", (new_status, task_id, user_id))
        db.commit()
    
    db.close()
    return redirect(url_for('manage_todos'))

@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user_id = session['user_id']
    db.execute("DELETE FROM todos WHERE id = ? AND user_id = ?", (task_id, user_id))
    db.commit()
    db.close()
    
    return redirect(url_for('manage_todos'))

@app.route('/logout')
def logout():
    if 'user' in session:
        log_security_event("LOGOUT", session['user'], request.remote_addr, "User logged out")
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    print("\n" + "="*50)
    print("SECURE TODO APPLICATION")
    print("="*50)
    print("Server running at: http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=True)