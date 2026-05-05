# ========================= IMPORTS =========================
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
import re, secrets, os, json

# ========================= SETUP =========================
basedir = os.path.abspath(os.path.dirname(__file__))
db_folder = os.path.join(basedir, 'database')
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(db_folder, 'lb.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ========================= MODELS =========================

class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), nullable=False, unique=True)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'))
    password_expiry_date = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)

    role = db.relationship('Role')

    def get_id(self):
        return str(self.user_id)

class Account(db.Model):
    __tablename__ = 'accounts'
    account_id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(150), nullable=False)
    account_number = db.Column(db.String(20), nullable=False)
    normal_side = db.Column(db.String(6), nullable=False)
    current_balance = db.Column(db.Numeric(15,2), default=0.00)
    is_active = db.Column(db.Integer, default=1)

# ========================= JOURNAL MODELS =========================

class JournalEntry(db.Model):
    __tablename__ = 'journal_entries'

    entry_id = db.Column(db.Integer, primary_key=True)
    entry_number = db.Column(db.String(20), unique=True, nullable=False)
    entry_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text)

    status = db.Column(db.String(20), default='PENDING')
    rejection_reason = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))

    creator = db.relationship('User')
    lines = db.relationship('JournalEntryLine', backref='entry', cascade="all, delete-orphan")


class JournalEntryLine(db.Model):
    __tablename__ = 'journal_entry_lines'

    line_id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.entry_id'))

    account_id = db.Column(db.Integer, db.ForeignKey('accounts.account_id'))
    debit = db.Column(db.Numeric(15,2), default=0.00)
    credit = db.Column(db.Numeric(15,2), default=0.00)

    account = db.relationship('Account')

# ========================= LOGIN =========================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========================= HELPERS =========================

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be 8+ chars"
    return True, ""

def generate_entry_number():
    count = JournalEntry.query.count() + 1
    return f"JE{str(count).zfill(5)}"

# ========================= ROUTES =========================

@app.route("/")
def home():
    return redirect(url_for("login"))

# ================= LOGIN =================
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username")).first()
        if user and check_password_hash(user.password_hash, request.form.get("password")):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid login", "error")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ================= JOURNAL ENTRY =================

@app.route("/journal-entries")
@login_required
def journal_entries():
    query = JournalEntry.query

    status = request.args.get("status")
    if status:
        query = query.filter_by(status=status)

    entries = query.order_by(JournalEntry.created_at.desc()).all()
    return render_template("journal_entries.html", entries=entries)

# CREATE
@app.route("/journal-entries/create", methods=["GET","POST"])
@login_required
def journal_entry_create():
    if request.method == "POST":
        entry = JournalEntry(
            entry_number=generate_entry_number(),
            entry_date=datetime.strptime(request.form.get("entry_date"), "%Y-%m-%d"),
            description=request.form.get("description"),
            created_by=current_user.user_id
        )

        total_debit = 0
        total_credit = 0

        for i in range(3):
            acc = request.form.get(f"account_id_{i}")
            if not acc:
                continue

            debit = float(request.form.get(f"debit_{i}") or 0)
            credit = float(request.form.get(f"credit_{i}") or 0)

            total_debit += debit
            total_credit += credit

            entry.lines.append(JournalEntryLine(
                account_id=int(acc),
                debit=debit,
                credit=credit
            ))

        if total_debit != total_credit:
            flash("Debits must equal credits", "error")
            return redirect(url_for("journal_entry_create"))

        db.session.add(entry)
        db.session.commit()

        flash("Entry created", "success")
        return redirect(url_for("journal_entries"))

    accounts = Account.query.filter_by(is_active=1).all()
    return render_template("journal_entry_create.html", accounts=accounts)

# DETAIL
@app.route("/journal-entries/<int:entry_id>")
@login_required
def journal_entry_detail(entry_id):
    entry = JournalEntry.query.get_or_404(entry_id)
    return render_template("journal_entry_detail.html", entry=entry)

# APPROVE
@app.route("/journal-entries/<int:entry_id>/approve")
@login_required
def approve_entry(entry_id):
    if current_user.role.role_name != "ROLE_MANAGER":
        flash("Access denied", "error")
        return redirect(url_for("journal_entries"))

    entry = JournalEntry.query.get_or_404(entry_id)

    for line in entry.lines:
        acc = line.account

        if acc.normal_side == "Debit":
            acc.current_balance += float(line.debit)
            acc.current_balance -= float(line.credit)
        else:
            acc.current_balance -= float(line.debit)
            acc.current_balance += float(line.credit)

    entry.status = "APPROVED"
    db.session.commit()

    flash("Approved", "success")
    return redirect(url_for("journal_entries"))

# REJECT
@app.route("/journal-entries/<int:entry_id>/reject", methods=["GET","POST"])
@login_required
def reject_entry(entry_id):
    if current_user.role.role_name != "ROLE_MANAGER":
        flash("Access denied", "error")
        return redirect(url_for("journal_entries"))

    entry = JournalEntry.query.get_or_404(entry_id)

    if request.method == "POST":
        entry.status = "REJECTED"
        entry.rejection_reason = request.form.get("reason")

        db.session.commit()
        flash("Rejected", "success")
        return redirect(url_for("journal_entries"))

    return render_template("reject_entry.html", entry=entry)

# ========================= INIT =========================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        if not Role.query.first():
            db.session.add_all([
                Role(role_name='ROLE_ADMIN'),
                Role(role_name='ROLE_MANAGER'),
                Role(role_name='ROLE_USER')
            ])
            db.session.commit()

        if not User.query.filter_by(username='admin').first():
            admin_role = Role.query.filter_by(role_name='ROLE_ADMIN').first()
            admin = User(
                username='admin',
                password_hash=generate_password_hash('Admin123!'),
                email='admin@test.com',
                first_name='Admin',
                last_name='User',
                date_of_birth=datetime(1990,1,1),
                role_id=admin_role.role_id
            )
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)
