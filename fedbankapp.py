#!/usr/bin/env python3
#
#___________        .___                   __  .__
#\_   _____/___   __| _/________________ _/  |_|__| ____   ____
# |    __)/ __ \ / __ |/ __ \_  __ \__  \\   __\  |/  _ \ /    \
# |     \\  ___// /_/ \  ___/|  | \// __ \|  | |  (  <_> )   |  \
# \___  / \___  >____ |\___  >__|  (____  /__| |__|\____/|___|  /
#     \/      \/     \/    \/           \/                    \/
#__________                __       _________.__              .__          __
#\______   \_____    ____ |  | __  /   _____/|__| _____  __ __|  | _____ _/  |_  ___________
# |    |  _/\__  \  /    \|  |/ /  \_____  \ |  |/     \|  |  \  | \__  \\   __\/  _ \_  __ \
# |    |   \ / __ \|   |  \    <   /        \|  |  Y Y  \  |  /  |__/ __ \|  | (  <_> )  | \/
# |______  /(____  /___|  /__|_ \ /_______  /|__|__|_|  /____/|____(____  /__|  \____/|__|
#        \/      \/     \/     \/         \/          \/                \/                   v1.2
#
# Written by Squ1rr3l
#
# Federation Bank Simulator — a tiny multi-user crypto-simulator.
#
# Features
# - User auth (login/logout), optional self-sign-up (toggle).
# - Wallets: username, auto-generated wallet address, balance (FCR), tx history.
# - Send FCR between wallets (by address).
# - Admin console:
#     • Mint (create) new FCR and credit any wallet
#     • Move funds between ANY two wallets
#     • Reset a user's password
#     • Create/disable users; toggle admin
#     • Quick user search
# - SQLite via SQLAlchemy. Passwords hashed with Werkzeug.
# - Single file, minimal deps, inline Jinja templates + CSS for sci-fi vibe.
#
# Run locally
# 1) python3 -m venv .venv && source .venv/bin/activate
# 2) pip install flask flask_sqlalchemy
# 3) python app.py  # runs on http://127.0.0.1:5000
#
# First run creates a default admin: user=admin, pass=admin (CHANGE THIS in Admin ▶ Users!)
#
# Notes
# - NOT real crypto. No blockchain. Purely a teaching/demo app.
# - For brevity, CSRF protection is omitted. Do not expose to the public internet without adding CSRF + HTTPS + stronger policies.


from __future__ import annotations
import os
import secrets
import string
import datetime as dt
from decimal import Decimal, ROUND_DOWN

from flask import (
    Flask, render_template_string, request, redirect, url_for, session,
    flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------- Config -----------------------
APP_NAME = "Federation Credits"
CURRENCY = "FCR"
ALLOW_SELF_SIGNUP = True  # set False to disable /register route
DECIMALS = 2  # like cents — keep it simple

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-'+secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///federation.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------------- Helpers -----------------------

def now_utc():
    return dt.datetime.utcnow()

def fmt_amount(amount: Decimal) -> str:
    q = Decimal(10) ** -DECIMALS
    return f"{amount.quantize(q, rounding=ROUND_DOWN)} {CURRENCY}"

def make_wallet_address() -> str:
    # A fun sci-fi flavored address like FCR-ORION-XXXX-XXXX
    stars = ["ORION","CYGNUS","DRACO","LYRA","PEGASUS","ANDROMEDA","PHOENIX","AURIGA"]
    blocks = [''.join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(4)) for __ in range(2)]
    return f"FCR-{secrets.choice(stars)}-{blocks[0]}-{blocks[1]}"

from sqlalchemy.orm import validates

# ----------------------- Models -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    wallet_address = db.Column(db.String(40), unique=True, nullable=False, default=make_wallet_address)
    balance_cents = db.Column(db.Integer, default=0, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_utc)

    @property
    def balance(self) -> Decimal:
        return Decimal(self.balance_cents) / Decimal(10**DECIMALS)

    def set_balance(self, amount: Decimal):
        self.balance_cents = int((amount * (10**DECIMALS)).to_integral_value(rounding=ROUND_DOWN))

    def credit(self, amount: Decimal):
        self.balance_cents += int(amount * (10**DECIMALS))

    def debit(self, amount: Decimal):
        cents = int(amount * (10**DECIMALS))
        if self.balance_cents < cents:
            raise ValueError("Insufficient funds")
        self.balance_cents -= cents

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class Tx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=now_utc, index=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # None for mint/burn
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    amount_cents = db.Column(db.Integer, nullable=False)
    kind = db.Column(db.String(20), nullable=False)  # 'transfer','mint','admin_move','reset','burn'
    memo = db.Column(db.String(200), default="")
    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])

    @property
    def amount(self) -> Decimal:
        return Decimal(self.amount_cents) / Decimal(10**DECIMALS)

# ----------------------- DB init -----------------------
with app.app_context():
    db.create_all()
    # bootstrap admin if none exists
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin')
        admin.wallet_address = make_wallet_address()
        admin.set_balance(Decimal('1000'))  # starter treasury for demos
        db.session.add(admin)
        db.session.commit()

# ----------------------- Auth utils -----------------------

def current_user() -> User | None:
    uid = session.get('uid')
    if not uid:
        return None
    return db.session.get(User, uid)

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

# ----------------------- Page rendering (FIX) -----------------------
def base_ctx(title: str, **kwargs):
    # NOTE: no raw 'body' here; we render body separately
    ctx = {
        'APP_NAME': APP_NAME,
        'CURRENCY': CURRENCY,
        'ALLOW_SELF_SIGNUP': ALLOW_SELF_SIGNUP,
        'title': title,
        'user': current_user(),
        **kwargs
    }
    return ctx

def render_page(body_tpl: str, **kwargs):
    """
    Render inner template first (so {{ url_for(...) }} etc. are evaluated),
    then inject into TPL_BASE.
    """
    ctx = base_ctx(**kwargs)
    body_html = render_template_string(body_tpl, **ctx)
    return render_template_string(TPL_BASE, **{**ctx, "body": body_html})

# ----------------------- Routes: public -----------------------
@app.route('/')
def index():
    if current_user():
        return redirect(url_for('dashboard'))
    return render_page(TPL_LANDING, title="Welcome")

@app.route('/register', methods=['GET','POST'])
def register():
    if not ALLOW_SELF_SIGNUP:
        abort(404)
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            flash("All fields required.", 'err')
        elif User.query.filter_by(username=username).first():
            flash("Username already taken.", 'err')
        else:
            u = User(username=username, wallet_address=make_wallet_address())
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Registration complete. You can sign in now.", 'ok')
            return redirect(url_for('login'))
    return render_page(TPL_REGISTER, title="Sign up")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            session['uid'] = user.id
            flash("Access granted.", 'ok')
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash("Invalid credentials or deactivated account.", 'err')
    return render_page(TPL_LOGIN, title="Log in")

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Sucessfully Logged Out.", 'ok')
    return redirect(url_for('login'))

# ----------------------- Routes: user wallet -----------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    txs_in = Tx.query.filter_by(to_user_id=user.id).order_by(Tx.created_at.desc()).limit(10).all()
    txs_out = Tx.query.filter_by(from_user_id=user.id).order_by(Tx.created_at.desc()).limit(10).all()
    return render_page(TPL_DASH, title="Your Wallet", user=user, txs_in=txs_in, txs_out=txs_out)

@app.route('/send', methods=['POST'])
@login_required
def send():
    sender = current_user()
    try:
        to_addr = request.form.get('to_addr','').strip().upper()
        amount = Decimal(request.form.get('amount','0').strip())
        memo = request.form.get('memo','')[:180]
        if amount <= 0:
            raise ValueError("Amount must be positive")
        q = Decimal(10) ** -DECIMALS
        amount = amount.quantize(q, rounding=ROUND_DOWN)
        recipient = User.query.filter_by(wallet_address=to_addr, is_active=True).first()
        if not recipient:
            raise ValueError("Destination address not found")
        if recipient.id == sender.id:
            raise ValueError("Cannot send to your own wallet")
        sender.debit(amount)
        recipient.credit(amount)
        tx = Tx(from_user_id=sender.id, to_user_id=recipient.id, amount_cents=int(amount*(10**DECIMALS)), kind='transfer', memo=memo)
        db.session.add(tx)
        db.session.commit()
        flash(f"Transmission sent: {fmt_amount(amount)} to {recipient.wallet_address}", 'ok')
    except Exception as e:
        db.session.rollback()
        flash(str(e), 'err')
    return redirect(url_for('dashboard'))

@app.route('/transactions')
@login_required
def transactions():
    # Global ledger for everyone (any logged-in user can view)
    txs = Tx.query.order_by(Tx.created_at.desc()).limit(500).all()
    return render_page(TPL_TXS, title="Ledger (Global)", txs=txs)

# ----------------------- Routes: admin console -----------------------
@app.route('/admin')
@admin_required
def admin_home():
    q = request.args.get('q','').strip()
    users = []
    if q:
        users = User.query.filter(
            (User.username.ilike(f"%{q}%")) | (User.wallet_address.ilike(f"%{q}%"))
        ).order_by(User.created_at.desc()).limit(50).all()
    else:
        users = User.query.order_by(User.created_at.desc()).limit(20).all()
    return render_page(TPL_ADMIN, title="Command Deck", users=users, q=q)

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def admin_create_user():
    try:
        username = request.form['username'].strip()
        password = request.form['password']
        is_admin = True if request.form.get('is_admin')=='on' else False
        if not username or not password:
            raise ValueError("Username and password required")
        if User.query.filter_by(username=username).first():
            raise ValueError("Username already exists")
        u = User(username=username, is_admin=is_admin, wallet_address=make_wallet_address())
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Account created.", 'ok')
    except Exception as e:
        db.session.rollback()
        flash(str(e), 'err')
    return redirect(url_for('admin_home'))

@app.route('/admin/toggle_active', methods=['POST'])
@admin_required
def admin_toggle_active():
    uid = int(request.form['uid'])
    u = db.session.get(User, uid)
    if not u:
        flash("User not found", 'err')
    else:
        u.is_active = not u.is_active
        db.session.commit()
        flash("User activation toggled.", 'ok')
    return redirect(url_for('admin_home'))

@app.route('/admin/toggle_admin', methods=['POST'])
@admin_required
def admin_toggle_admin():
    uid = int(request.form['uid'])
    u = db.session.get(User, uid)
    if not u:
        flash("User not found", 'err')
    else:
        u.is_admin = not u.is_admin
        db.session.commit()
        flash("Admin status updated.", 'ok')
    return redirect(url_for('admin_home'))

@app.route('/admin/reset_password', methods=['POST'])
@admin_required
def admin_reset_password():
    uid = int(request.form['uid'])
    newpass = request.form['newpass']
    u = db.session.get(User, uid)
    if not u:
        flash("User not found", 'err')
    elif not newpass:
        flash("New password required", 'err')
    else:
        u.set_password(newpass)
        db.session.commit()
        flash("Password reset.", 'ok')
    return redirect(url_for('admin_home'))

@app.route('/admin/mint', methods=['POST'])
@admin_required
def admin_mint():
    try:
        to_addr = request.form['to_addr'].strip().upper()
        amount = Decimal(request.form['amount'])
        memo = request.form.get('memo','')[:180]
        if amount <= 0:
            raise ValueError("Amount must be positive")
        q = Decimal(10) ** -DECIMALS
        amount = amount.quantize(q, rounding=ROUND_DOWN)
        user = User.query.filter_by(wallet_address=to_addr, is_active=True).first()
        if not user:
            raise ValueError("Destination address not found")
        user.credit(amount)
        tx = Tx(from_user_id=None, to_user_id=user.id, amount_cents=int(amount*(10**DECIMALS)), kind='mint', memo=memo or 'Minted by Admin')
        db.session.add(tx)
        db.session.commit()
        flash(f"Minted {fmt_amount(amount)} to {user.wallet_address}", 'ok')
    except Exception as e:
        db.session.rollback()
        flash(str(e), 'err')
    return redirect(url_for('admin_home'))

@app.route('/admin/move', methods=['POST'])
@admin_required
def admin_move():
    try:
        from_addr = request.form['from_addr'].strip().upper()
        to_addr = request.form['to_addr'].strip().upper()
        amount = Decimal(request.form['amount'])
        memo = request.form.get('memo','')[:180]
        if amount <= 0:
            raise ValueError("Amount must be positive")
        q = Decimal(10) ** -DECIMALS
        amount = amount.quantize(q, rounding=ROUND_DOWN)
        sender = User.query.filter_by(wallet_address=from_addr, is_active=True).first()
        recipient = User.query.filter_by(wallet_address=to_addr, is_active=True).first()
        if not sender or not recipient:
            raise ValueError("Both addresses must be valid and active")
        if sender.id == recipient.id:
            raise ValueError("Addresses must differ")
        sender.debit(amount)
        recipient.credit(amount)
        tx = Tx(from_user_id=sender.id, to_user_id=recipient.id, amount_cents=int(amount*(10**DECIMALS)), kind='admin_move', memo=memo or 'Admin move')
        db.session.add(tx)
        db.session.commit()
        flash(f"Moved {fmt_amount(amount)} from {sender.wallet_address} to {recipient.wallet_address}", 'ok')
    except Exception as e:
        db.session.rollback()
        flash(str(e), 'err')
    return redirect(url_for('admin_home'))

# ----------------------- Routes: user directory (non-admin search) -----------------------
@app.route('/directory')
@login_required
def directory():
    """
    Non-admin user directory to find wallet addresses.
    - Lists only active users
    - Search by username (case-insensitive) or wallet address (case-insensitive)
    - Limits results to 50 to avoid huge responses
    """
    q = request.args.get('q', '').strip()
    base = User.query.filter_by(is_active=True)

    if q:
        # Case-insensitive match on username; normalize wallet address to uppercase for convenience
        users = base.filter(
            (User.username.ilike(f"%{q}%")) | (User.wallet_address.ilike(f"%{q.upper()}%"))
        ).order_by(User.username.asc()).limit(50).all()
    else:
        # Default: show a small, alphabetical slice of users
        users = base.order_by(User.username.asc()).limit(20).all()

    return render_page(TPL_DIRECTORY, title="User Directory", users=users, q=q)


# ----------------------- Templates -----------------------

TPL_BASE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ APP_NAME }} · {{ title }}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Rajdhani:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root{
      --bg: #0a0f1e; --panel:#0f1730; --accent:#7cf0ff; --accent2:#b892ff; --text:#e6f1ff; --muted:#9bb3c7; --ok:#3ee07a; --err:#ff5c7a;
    }
    *{box-sizing:border-box}
    body{margin:0; background: radial-gradient(1200px 600px at 10% -10%, #152043, transparent), radial-gradient(800px 400px at 90% 10%, #2b1359, transparent), var(--bg); color:var(--text); font-family: 'Rajdhani', sans-serif;}
    header{display:flex;gap:16px;align-items:center; padding:16px 24px; background:linear-gradient(90deg, #0f1730, transparent); border-bottom:1px solid #1d2a54}
    header h1{font-family:'Orbitron', sans-serif; font-size:20px; margin:0; letter-spacing:1.5px}
    header nav{margin-left:auto; display:flex; gap:12px}
    a{color:var(--accent)}
    .btn{display:inline-block; padding:10px 14px; border:1px solid #2846a5; background:linear-gradient(180deg,#17224b,#0d1430); color:#cfe6ff; text-decoration:none; border-radius:10px; box-shadow:inset 0 0 10px rgba(124,240,255,.15);}
    .btn:hover{box-shadow:0 0 12px rgba(124,240,255,.35)}
    .btn-danger{border-color:#7a1f32; background:linear-gradient(180deg,#3b0e17,#18060a); color:#ffd0d8}
    .btn-ok{border-color:#1d6d47; background:linear-gradient(180deg,#0f2b22,#0a1d17); color:#ceffe4}
    main{max-width:980px; margin:24px auto; padding:0 16px}
    .card{background:rgba(15,23,48,.8); border:1px solid #24356e; border-radius:16px; padding:18px; box-shadow: 0 0 40px rgba(124,240,255,.05)}
    .grid{display:grid; gap:16px}
    .grid-2{grid-template-columns:1fr 1fr}
    .muted{color:var(--muted)}
    .mono{font-family: ui-monospace, SFMono-Regular, Menlo, monospace}
    form .row{display:flex; gap:12px; flex-wrap:wrap}
    input,select{background:#0b1124; border:1px solid #2a3a76; color:var(--text); padding:10px 12px; border-radius:10px; width:100%}
    label{display:block; font-size:14px; color:#bcd0ff}
    table{width:100%; border-collapse:collapse}
    th,td{padding:10px; border-bottom:1px solid #1b2b5a; text-align:left}
    .flash{margin:10px 0; padding:10px 12px; border-radius:10px}
    .ok{background:rgba(62,224,122,.1); border:1px solid #256a45}
    .err{background:rgba(255,92,122,.08); border:1px solid #7a2034}
    .tag{display:inline-block; padding:2px 8px; border:1px solid #2a3a76; border-radius:999px; font-size:12px; color:#a6c2ff}
  </style>
</head>
<body>
  <header>
    <h1>⟡ {{ APP_NAME }} · Federation Credits ({{ CURRENCY }})</h1>
    <nav>
      {% if user %}
        <a class="btn" href="{{ url_for('dashboard') }}">Wallet</a>
        <a class="btn" href="{{ url_for('directory') }}">Directory</a>
        <a class="btn" href="{{ url_for('transactions') }}">Transactions</a>
        {% if user.is_admin %}<a class="btn" href="{{ url_for('admin_home') }}">Admin</a>{% endif %}
        <a class="btn btn-danger" href="{{ url_for('logout') }}">Log out</a>
      {% else %}
        {% if ALLOW_SELF_SIGNUP %}<a class="btn" href="{{ url_for('register') }}">Sign up</a>{% endif %}
        <a class="btn" href="{{ url_for('login') }}">Log in</a>
      {% endif %}
    </nav>
  </header>
  <main>
    {% for cat,msg in get_flashed_messages(with_categories=true) %}
      <div class="flash {{ 'ok' if cat=='ok' else 'err' }}">{{ msg }}</div>
    {% endfor %}
    <div class="card">{% block body %}{{ body|safe }}{% endblock %}</div>
  </main>
</body>
</html>
"""

TPL_LANDING = r"""
<h2>Welcome to the Federation Banking Guild</h2>
<p class="muted">Please either login or sign up to transact in <strong>Federation Credits ({{ CURRENCY }})</strong>. The Federation thanks you.</p>
<p>
  {% if ALLOW_SELF_SIGNUP %}<a class="btn btn-ok" href="{{ url_for('register') }}">Sign Up</a>{% endif %}
  <a class="btn" href="{{ url_for('login') }}">Log In</a>
</p>
"""

TPL_REGISTER = r"""
<h2>Sign Up</h2>
<form method="post">
  <div class="grid grid-2">
    <div>
      <label>Username</label>
      <input name="username" required />
    </div>
    <div>
      <label>Password</label>
      <input type="password" name="password" required />
    </div>
  </div>
  <p><button class="btn btn-ok" type="submit">Create Account</button></p>
  <p class="muted">Already have clearance? <a href="{{ url_for('login') }}">Log in</a>.</p>
</form>
"""

TPL_LOGIN = r"""
<h2>Log In</h2>
<form method="post">
  <div class="grid grid-2">
    <div>
      <label>Username</label>
      <input name="username" required />
    </div>
    <div>
      <label>Password</label>
      <input type="password" name="password" required />
    </div>
  </div>
  <p><button class="btn" type="submit">Submit</button></p>
</form>
"""

TPL_DASH = r"""
<h2>Your Wallet</h2>
<div class="grid grid-2">
  <section>
    <h3>Wallet</h3>
    <p><span class="muted">Citizen:</span> <strong>{{ user.username }}</strong></p>
    <p><span class="muted">Address:</span> <span class="mono">{{ user.wallet_address }}</span></p>
    <p><span class="muted">Balance:</span> <strong>{{ '%.2f' % user.balance }} {{ CURRENCY }}</strong></p>
  </section>
  <section>
    <h3>Send {{ CURRENCY }}</h3>
    <form method="post" action="{{ url_for('send') }}">
      <div class="row">
        <div style="flex:2 1 280px">
          <label>To Address</label>
          <input name="to_addr" placeholder="FCR-ORION-XXXX-YYYY" required />
        </div>
        <div style="flex:1 1 160px">
          <label>Amount ({{ CURRENCY }})</label>
          <input name="amount" type="number" min="0.01" step="0.01" required />
        </div>
      </div>
      <label>Memo (optional)</label>
      <input name="memo" placeholder="For cargo fuel" />
      <p><button class="btn btn-ok" type="submit">Send</button></p>
    </form>
  </section>
</div>

<div class="grid grid-2">
  <section>
    <h3>Incoming Credits</h3>
    <table>
      <tr><th>When</th><th>From</th><th>Amount</th><th>Memo</th></tr>
      {% for t in txs_in %}
      <tr>
        <td>{{ t.created_at.strftime('%Y-%m-%d %H:%M') }}Z</td>
        <td class="mono">{{ (t.from_user_id and ({}[t.from_user_id].wallet_address if {} else '')) or 'MINT' }}</td>
        <td>{{ '%.2f' % t.amount }} {{ CURRENCY }}</td>
        <td class="muted">{{ t.memo }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4" class="muted">Nothing yet.</td></tr>
      {% endfor %}
    </table>
  </section>
  <section>
    <h3>Outgoing Credits</h3>
    <table>
      <tr><th>When</th><th>To</th><th>Amount</th><th>Memo</th></tr>
      {% for t in txs_out %}
      <tr>
        <td>{{ t.created_at.strftime('%Y-%m-%d %H:%M') }}Z</td>
        <td class="mono">{{ {}[t.to_user_id].wallet_address if {} else t.to_user_id }}</td>
        <td>{{ '%.2f' % t.amount }} {{ CURRENCY }}</td>
        <td class="muted">{{ t.memo }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4" class="muted">Nothing yet.</td></tr>
      {% endfor %}
    </table>
  </section>
</div>
"""
# For compactness, in the dashboard we won't precompute users_map in Python; keep template simple
# Replace users_map usages with safer inline rendering
TPL_DASH = TPL_DASH.replace("users_map[", "{}[")

TPL_TXS = r"""
<h2>Ledger (Global)</h2>
<table>
  <tr><th>When (UTC)</th><th>Type</th><th>From</th><th>To</th><th>Amount</th><th>Memo</th></tr>
  {% for t in txs %}
  <tr>
    <td>{{ t.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
    <td><span class="tag">{{ t.kind }}</span></td>
    <td class="mono">
      {% if t.from_user %}
        {{ t.from_user.username }} · {{ t.from_user.wallet_address }}
      {% else %}
        MINT
      {% endif %}
    </td>
    <td class="mono">
      {% if t.to_user %}
        {{ t.to_user.username }} · {{ t.to_user.wallet_address }}
      {% else %}
        —
      {% endif %}
    </td>
    <td>{{ '%.2f' % t.amount }} {{ CURRENCY }}</td>
    <td class="muted">{{ t.memo }}</td>
  </tr>
  {% else %}
  <tr><td colspan="6" class="muted">No transactions logged yet.</td></tr>
  {% endfor %}
</table>
"""

TPL_ADMIN = r"""
<h2>Command Deck</h2>
<form method="get" action="{{ url_for('admin_home') }}">
  <input name="q" value="{{ q }}" placeholder="Search users or addresses" />
  <button class="btn" type="submit">Scan</button>
</form>

<div class="grid grid-2" style="margin-top:16px">
  <section>
    <h3>Create New User</h3>
    <form method="post" action="{{ url_for('admin_create_user') }}">
      <label>Username</label>
      <input name="username" required />
      <label>Password</label>
      <input type="password" name="password" required />
      <label><input type="checkbox" name="is_admin" /> Grant Admin</label>
      <p><button class="btn btn-ok" type="submit">Add User</button></p>
    </form>
  </section>

  <section>
    <h3>Mint {{ CURRENCY }}</h3>
    <form method="post" action="{{ url_for('admin_mint') }}">
      <label>To Address</label>
      <input name="to_addr" placeholder="FCR-..." required />
      <label>Amount ({{ CURRENCY }})</label>
      <input name="amount" type="number" min="0.01" step="0.01" required />
      <label>Memo</label>
      <input name="memo" placeholder="Mint reason" />
      <p><button class="btn btn-ok" type="submit">Mint</button></p>
    </form>
  </section>
</div>

<div class="grid grid-2">
  <section>
    <h3>Admin Move (Any → Any)</h3>
    <form method="post" action="{{ url_for('admin_move') }}">
      <label>From Address</label>
      <input name="from_addr" placeholder="FCR-..." required />
      <label>To Address</label>
      <input name="to_addr" placeholder="FCR-..." required />
      <label>Amount ({{ CURRENCY }})</label>
      <input name="amount" type="number" min="0.01" step="0.01" required />
      <label>Memo</label>
      <input name="memo" placeholder="Reason" />
      <p><button class="btn" type="submit">Execute Move</button></p>
    </form>
  </section>

  <section>
    <h3>User Controls</h3>
    <table>
      <tr><th>User</th><th>Address</th><th>Balance</th><th>Flags</th><th>Actions</th></tr>
      {% for u in users %}
      <tr>
        <td>{{ u.username }}</td>
        <td class="mono">{{ u.wallet_address }}</td>
        <td>{{ '%.2f' % (u.balance_cents / 100) }} {{ CURRENCY }}</td>
        <td>
          {% if u.is_admin %}<span class="tag">admin</span>{% endif %}
          {% if not u.is_active %}<span class="tag">deactivated</span>{% endif %}
        </td>
        <td>
          <form style="display:inline" method="post" action="{{ url_for('admin_toggle_active') }}">
            <input type="hidden" name="uid" value="{{ u.id }}" />
            <button class="btn" type="submit">{{ 'Activate' if not u.is_active else 'Deactivate' }}</button>
          </form>
          <form style="display:inline" method="post" action="{{ url_for('admin_toggle_admin') }}">
            <input type="hidden" name="uid" value="{{ u.id }}" />
            <button class="btn" type="submit">{{ 'Grant Admin' if not u.is_admin else 'Revoke Admin' }}</button>
          </form>
          <form style="display:inline" method="post" action="{{ url_for('admin_reset_password') }}">
            <input type="hidden" name="uid" value="{{ u.id }}" />
            <input style="width:140px" name="newpass" placeholder="New pass" required />
            <button class="btn btn-danger" type="submit">Reset PW</button>
          </form>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="5" class="muted">No matches.</td></tr>
      {% endfor %}
    </table>
  </section>
</div>
"""

TPL_DIRECTORY = r"""
<h2>User Directory</h2>
<form method="get" action="{{ url_for('directory') }}">
  <div class="row">
    <div style="flex: 2 1 360px">
      <label>Search by Username or Address</label>
      <input name="q" value="{{ q }}" placeholder="e.g. 'kara' or 'FCR-ORION-ABCD-1234'" />
    </div>
    <div style="align-self:end">
      <button class="btn" type="submit">Search</button>
    </div>
  </div>
  <p class="muted" style="margin-top:8px">
    Showing {{ users|length }} result{{ '' if users|length==1 else 's' }}.
    {% if not q %}Tip: type to search across active users.{% endif %}
  </p>
</form>

<table>
  <tr>
    <th>User</th>
    <th>Wallet Address</th>
    <th></th>
  </tr>
  {% for u in users %}
  <tr>
    <td>
      {% if user and u.id == user.id %}
        <strong>{{ u.username }}</strong> <span class="tag">you</span>
      {% else %}
        {{ u.username }}
      {% endif %}
    </td>
    <td class="mono">{{ u.wallet_address }}</td>
    <td>
      <button class="btn" type="button" onclick="copyAddr('{{ u.wallet_address }}')">Copy</button>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="3" class="muted">No matches found.</td></tr>
  {% endfor %}
</table>

<script>
  async function copyAddr(text) {
    try {
      await navigator.clipboard.writeText(text);
      alert('Address copied to clipboard: ' + text);
    } catch (e) {
      alert('Could not copy address. Please copy manually.');
    }
  }
</script>
"""


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',                 # listen on LAN
        port=int(os.environ.get('PORT', 5000)),
        debug=True
    )

