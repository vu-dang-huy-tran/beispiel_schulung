#joels änderung wird so geschrieben
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, g
import os
import sqlite3
from functools import wraps
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Set a secret key for session encryption

# Database setup
DATABASE = 'users.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    db = get_db()
    db.execute(query, args)
    db.commit()

# Ensure the database exists
def create_tables():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Check if default users exist
    admin = c.execute('SELECT * FROM users WHERE email = ?', ('admin@example.com',)).fetchone()
    if not admin:
        admin_pw = hashlib.md5("123".encode()).hexdigest()
        c.execute('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
                 ('admin@example.com', admin_pw, 'Admin User', 'admin'))
    
    user = c.execute('SELECT * FROM users WHERE email = ?', ('user@example.com',)).fetchone()
    if not user:
        user_pw = hashlib.md5("user123".encode()).hexdigest()
        c.execute('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
                 ('user@example.com', user_pw, 'Regular User', 'user'))
    
    conn.commit()
    conn.close()

# Create tables on startup
create_tables()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        remember = 'remember' in request.form
        
        user = query_db('SELECT * FROM users WHERE email = ?', [email], one=True)
        
        if user and user['password'] == password:
            session['user'] = user['email']
            session['name'] = user['name']
            session['role'] = user['role']
            session.permanent = remember  # Set session permanence based on remember checkbox
            
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        
        # Check if user already exists
        existing_user = query_db('SELECT * FROM users WHERE email = ?', [email], one=True)
        if existing_user:
            error = 'Email already registered. Please use a different email.'
        else:
            # Create new user
            hashed_password = hashlib.md5(password.encode()).hexdigest()
            
            try:
                insert_db('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
                         [email, hashed_password, name])
                flash('Account created successfully! Please login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                error = f'An error occurred: {str(e)}'
    
    return render_template('signup.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('name', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Prepare statistics for admin users
    stats = {}
    if session.get('role') == 'admin':
        total_users = query_db('SELECT COUNT(*) as count FROM users', one=True)['count']
        admin_users = query_db('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin'], one=True)['count']
        regular_users = query_db('SELECT COUNT(*) as count FROM users WHERE role = ?', ['user'], one=True)['count']
        
        stats = {
            'total_users': total_users,
            'admin_users': admin_users,
            'regular_users': regular_users
        }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/users')
@login_required
def list_users():
    # Only admins can see the user list
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users = query_db('SELECT * FROM users')
    return render_template('users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Only admins can edit users
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('list_users'))
    
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        role = request.form['role']
        
        # Check if changing password
        new_password = request.form.get('password')
        
        try:
            if new_password:
                # Update with new password
                hashed_password = hashlib.md5(new_password.encode()).hexdigest()
                insert_db('''
                    UPDATE users 
                    SET email = ?, name = ?, role = ?, password = ? 
                    WHERE id = ?
                ''', [email, name, role, hashed_password, user_id])
            else:
                # Update without changing password
                insert_db('''
                    UPDATE users 
                    SET email = ?, name = ?, role = ? 
                    WHERE id = ?
                ''', [email, name, role, user_id])
                
            flash('User updated successfully', 'success')
            return redirect(url_for('list_users'))
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'error')
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    # Only admins can delete users
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Don't allow deleting self
    user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    if user['email'] == session.get('user'):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('list_users'))
    
    try:
        insert_db('DELETE FROM users WHERE id = ?', [user_id])
        flash('User deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('list_users'))

@app.route('/huyistsuper')
def hello2():
    return "<h1>GEILE WEBSEITE 2</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8000', debug=True)
