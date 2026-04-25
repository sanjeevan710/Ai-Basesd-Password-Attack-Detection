from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import sqlite3
import random
from datetime import datetime, timedelta
import os
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# ── CSRF Protection ────────────────────────────────────────
csrf = CSRFProtect(app)

# ── Resolve paths ──────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'database.db')

# ── Flask-Login ────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ── Load ML Models ─────────────────────────────────────────
try:
    rf_model = joblib.load(os.path.join(BASE_DIR, app.config['MODEL_PATH_RF']))
    lr_model = joblib.load(os.path.join(BASE_DIR, app.config['MODEL_PATH_LR']))
    print("✅ Models loaded successfully.")
except FileNotFoundError as e:
    print(f"❌ CRITICAL: Model not found → {e}")
    rf_model = None
    lr_model = None

# ── DB Helper ──────────────────────────────────────────────
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── User Class ─────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id       = id
        self.username = username
        self.email    = email
        self.role     = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['email'], user['role'])
    return None

# ── Helper: generate synthetic test data (same seed as train_model.py) ──
def _generate_test_data():
    np.random.seed(42)
    n = 5000
    data = {'failed_attempts': [], 'login_frequency': [], 'access_time_hour': [],
            'is_new_device': [], 'is_suspicious_ip': [], 'location_change': [], 'label': []}
    for _ in range(n):
        label = np.random.choice([0, 1], p=[0.7, 0.3])
        if label == 0:
            data['failed_attempts'].append(np.random.choice([0, 1, 2], p=[0.8, 0.15, 0.05]))
            data['login_frequency'].append(np.random.randint(1, 5))
            data['access_time_hour'].append(np.random.randint(6, 23))
            data['is_new_device'].append(np.random.choice([0, 1], p=[0.9, 0.1]))
            data['is_suspicious_ip'].append(0)
            data['location_change'].append(np.random.choice([0, 1], p=[0.95, 0.05]))
        else:
            data['failed_attempts'].append(np.random.randint(3, 15))
            data['login_frequency'].append(np.random.randint(5, 50))
            data['access_time_hour'].append(np.random.randint(0, 24))
            data['is_new_device'].append(1)
            data['is_suspicious_ip'].append(np.random.choice([0, 1], p=[0.4, 0.6]))
            data['location_change'].append(np.random.choice([0, 1], p=[0.3, 0.7]))
        data['label'].append(label)
    df = pd.DataFrame(data)
    X = df.drop('label', axis=1)
    y = df['label']
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    return X_test, y_test

# ── Routes ─────────────────────────────────────────────────

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username   = request.form['username']
        password   = request.form['password']
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')

        conn      = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        now_utc            = datetime.utcnow()
        one_hour_ago       = (now_utc - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        twenty_four_hours_ago = (now_utc - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')

        # ── Check manually blocked IPs ──────────────────────
        is_ip_blocked = conn.execute(
            'SELECT 1 FROM blocked_ips WHERE ip_address = ?', (ip_address,)
        ).fetchone()
        if is_ip_blocked:
            conn.close()
            flash('Your IP address has been blocked by the administrator.', 'error')
            return redirect(url_for('login'))
        # ────────────────────────────────────────────────────

        failed_attempts = conn.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ? AND success = 0 AND timestamp > ?
        ''', (ip_address, one_hour_ago)).fetchone()[0]

        login_frequency = conn.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ? AND timestamp > ?
        ''', (ip_address, twenty_four_hours_ago)).fetchone()[0]

        access_time_hour = now_utc.hour

        is_new_device = 0
        if user_data:
            prev_device = conn.execute('''
                SELECT COUNT(*) FROM login_attempts
                WHERE user_id = ? AND user_agent = ? AND success = 1
            ''', (user_data['id'], user_agent)).fetchone()[0]
            if prev_device == 0:
                is_new_device = 1
        else:
            is_new_device = 1

        is_suspicious_ip = 0
        if ip_address not in ['127.0.0.1', '::1']:
            if random.random() < 0.05:
                is_suspicious_ip = 1

        location_change = 1 if failed_attempts >= 3 else 0

        print(f"Login: user={username}, ip={ip_address}, failed={failed_attempts}, freq={login_frequency}")

        # ── Hard rule: block after 5 failed attempts ────────
        if failed_attempts >= 5:
            conn.execute(
                'INSERT INTO attack_logs (user_id, ip_address, attack_type, action_taken) VALUES (?, ?, ?, ?)',
                (user_data['id'] if user_data else None, ip_address, 'Brute Force', 'Blocked')
            )
            conn.execute(
                'INSERT INTO login_attempts (user_id, ip_address, user_agent, success, ml_prediction) VALUES (?, ?, ?, ?, ?)',
                (user_data['id'] if user_data else None, ip_address, user_agent, 0, 1)
            )
            conn.commit()
            conn.close()
            flash('Suspicious activity detected! Access temporarily blocked.', 'error')
            return redirect(url_for('login'))

        # ── ML Prediction ───────────────────────────────────
        if rf_model:
            features = pd.DataFrame(
                [[failed_attempts, login_frequency, access_time_hour,
                  is_new_device, is_suspicious_ip, location_change]],
                columns=['failed_attempts', 'login_frequency', 'access_time_hour',
                         'is_new_device', 'is_suspicious_ip', 'location_change']
            )
            prediction  = rf_model.predict(features)[0]
            probability = rf_model.predict_proba(features)[0][1]
        else:
            prediction  = 0
            probability = 0

        print(f"  → Prediction={prediction}, Prob={probability:.2f}")

        if prediction == 1 or probability > 0.5:
            conn.execute(
                'INSERT INTO attack_logs (user_id, ip_address, attack_type, action_taken) VALUES (?, ?, ?, ?)',
                (user_data['id'] if user_data else None, ip_address, 'Suspicious Login Behavior', 'Blocked')
            )
            conn.execute(
                'INSERT INTO login_attempts (user_id, ip_address, user_agent, success, ml_prediction) VALUES (?, ?, ?, ?, ?)',
                (user_data['id'] if user_data else None, ip_address, user_agent, 0, 1)
            )
            conn.commit()
            conn.close()
            flash('Suspicious activity detected! Access temporarily blocked.', 'error')
            return redirect(url_for('login'))

        # ── Credential check ────────────────────────────────
        if user_data and check_password_hash(user_data['password_hash'], password):
            user_obj = User(user_data['id'], user_data['username'], user_data['email'], user_data['role'])
            login_user(user_obj)
            conn.execute(
                'INSERT INTO login_attempts (user_id, ip_address, user_agent, success, ml_prediction) VALUES (?, ?, ?, ?, ?)',
                (user_data['id'], ip_address, user_agent, 1, 0)
            )
            conn.commit()
            conn.close()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn.execute(
                'INSERT INTO login_attempts (user_id, ip_address, user_agent, success, ml_prediction) VALUES (?, ?, ?, ?, ?)',
                (user_data['id'] if user_data else None, ip_address, user_agent, 0, 0)
            )
            conn.commit()
            conn.close()
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('index.html', title='Login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username         = request.form['username']
        email            = request.form['email']
        password         = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        conn          = get_db_connection()
        existing_user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?', (username, email)
        ).fetchone()
        if existing_user:
            conn.close()
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (username, email, password_hash, 'user')
        )
        conn.commit()
        conn.close()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register')


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    logs = conn.execute(
        'SELECT * FROM login_attempts WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
        (current_user.id,)
    ).fetchall()

    last_login = conn.execute(
        'SELECT timestamp FROM login_attempts WHERE user_id = ? AND success = 1 ORDER BY timestamp DESC LIMIT 1 OFFSET 1',
        (current_user.id,)
    ).fetchone()
    last_login_time = last_login['timestamp'] if last_login else None

    current_month = datetime.utcnow().strftime('%Y-%m')
    login_count = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE user_id = ? AND strftime('%Y-%m', timestamp) = ?",
        (current_user.id, current_month)
    ).fetchone()[0]

    # ── Chart data: logins per day (last 7 days) ────────────
    daily_labels  = []
    daily_success = []
    daily_failed  = []
    for i in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        label = (datetime.utcnow() - timedelta(days=i)).strftime('%b %d')
        daily_labels.append(label)
        ok = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE user_id = ? AND success = 1 AND strftime('%Y-%m-%d', timestamp) = ?",
            (current_user.id, day)
        ).fetchone()[0]
        fail = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE user_id = ? AND success = 0 AND strftime('%Y-%m-%d', timestamp) = ?",
            (current_user.id, day)
        ).fetchone()[0]
        daily_success.append(ok)
        daily_failed.append(fail)

    conn.close()

    logs_list = []
    for log in logs:
        risk = 0.9 if log['ml_prediction'] == 1 else 0.1
        if not log['success']:
            risk += 0.2
        logs_list.append({
            'timestamp':  log['timestamp'],
            'ip_address': log['ip_address'],
            'user_agent': log['user_agent'],
            'success':    log['success'],
            'risk_score': min(risk, 1.0)
        })

    return render_template('dashboard.html',
                           title='Dashboard',
                           user_logs=logs_list,
                           last_login=last_login_time,
                           login_count=login_count,
                           daily_labels=daily_labels,
                           daily_success=daily_success,
                           daily_failed=daily_failed)


@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'error')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()

    attack_logs = conn.execute('''
        SELECT a.*, u.username
        FROM attack_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC LIMIT 50
    ''').fetchall()

    attack_count = conn.execute('SELECT COUNT(*) FROM attack_logs').fetchone()[0]

    blocked_ips_count = conn.execute(
        'SELECT COUNT(DISTINCT ip_address) FROM attack_logs WHERE action_taken = "Blocked"'
    ).fetchone()[0]

    blocked_ips = conn.execute(
        'SELECT * FROM blocked_ips ORDER BY blocked_at DESC'
    ).fetchall()

    # ── Chart data: attack types breakdown ──────────────────
    attack_types_raw = conn.execute(
        'SELECT attack_type, COUNT(*) as cnt FROM attack_logs GROUP BY attack_type'
    ).fetchall()
    attack_type_labels  = [r['attack_type'] for r in attack_types_raw]
    attack_type_counts  = [r['cnt']         for r in attack_types_raw]

    # ── Chart data: attacks per day (last 7 days) ───────────
    timeline_labels = []
    timeline_counts = []
    for i in range(6, -1, -1):
        day   = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        label = (datetime.utcnow() - timedelta(days=i)).strftime('%b %d')
        cnt   = conn.execute(
            "SELECT COUNT(*) FROM attack_logs WHERE strftime('%Y-%m-%d', timestamp) = ?",
            (day,)
        ).fetchone()[0]
        timeline_labels.append(label)
        timeline_counts.append(cnt)

    conn.close()

    return render_template('admin.html',
                           title='Admin Panel',
                           attack_logs=attack_logs,
                           attack_count=attack_count,
                           blocked_ips_count=blocked_ips_count,
                           blocked_ips=blocked_ips,
                           attack_type_labels=attack_type_labels,
                           attack_type_counts=attack_type_counts,
                           timeline_labels=timeline_labels,
                           timeline_counts=timeline_counts)


# ── Block / Unblock IP ──────────────────────────────────────
@app.route('/admin/block-ip', methods=['POST'])
@login_required
def block_ip():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    ip     = request.form.get('ip_address', '').strip()
    reason = request.form.get('reason', 'Manually blocked by admin').strip()

    if not ip:
        flash('No IP address provided.', 'error')
        return redirect(url_for('admin'))

    conn = get_db_connection()
    existing = conn.execute('SELECT 1 FROM blocked_ips WHERE ip_address = ?', (ip,)).fetchone()
    if existing:
        flash(f'IP {ip} is already blocked.', 'error')
    else:
        conn.execute(
            'INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)',
            (ip, reason, current_user.username)
        )
        conn.commit()
        flash(f'IP {ip} has been blocked successfully.', 'success')
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/unblock-ip', methods=['POST'])
@login_required
def unblock_ip():
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    ip = request.form.get('ip_address', '').strip()
    if not ip:
        flash('No IP address provided.', 'error')
        return redirect(url_for('admin'))

    conn = get_db_connection()
    conn.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip,))
    conn.commit()
    conn.close()
    flash(f'IP {ip} has been unblocked.', 'success')
    return redirect(url_for('admin'))


# ── Model Comparison ────────────────────────────────────────
@app.route('/model-comparison')
@login_required
def model_comparison():
    if current_user.role != 'admin':
        flash('Access denied. Admin rights required.', 'error')
        return redirect(url_for('dashboard'))

    metrics = None
    error   = None

    if rf_model and lr_model:
        try:
            X_test, y_test = _generate_test_data()

            rf_pred = rf_model.predict(X_test)
            lr_pred = lr_model.predict(X_test)

            def fmt(v): return round(float(v) * 100, 2)

            metrics = {
                'rf': {
                    'accuracy':  fmt(accuracy_score(y_test, rf_pred)),
                    'precision': fmt(precision_score(y_test, rf_pred, zero_division=0)),
                    'recall':    fmt(recall_score(y_test, rf_pred, zero_division=0)),
                    'f1':        fmt(f1_score(y_test, rf_pred, zero_division=0)),
                },
                'lr': {
                    'accuracy':  fmt(accuracy_score(y_test, lr_pred)),
                    'precision': fmt(precision_score(y_test, lr_pred, zero_division=0)),
                    'recall':    fmt(recall_score(y_test, lr_pred, zero_division=0)),
                    'f1':        fmt(f1_score(y_test, lr_pred, zero_division=0)),
                }
            }
        except Exception as e:
            error = str(e)
    else:
        error = 'Models not loaded. Please run train_model.py first.'

    return render_template('model_comparison.html',
                           title='Model Comparison',
                           metrics=metrics,
                           error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ── CSRF Error Handler ──────────────────────────────────────
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Session expired or invalid request. Please try again.', 'error')
    return redirect(url_for('login'))


if __name__ == '__main__':
    db_file = os.path.join(BASE_DIR, 'database.db')
    if not os.path.exists(db_file):
        print("Initializing database...")
        import db
        db.init_db()
    app.run(debug=True, port=5000)