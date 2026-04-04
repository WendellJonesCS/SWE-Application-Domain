from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
import re, secrets, os, json

basedir = os.path.abspath(os.path.dirname(__file__))
db_folder = os.path.join(basedir, 'database')
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(db_folder, 'lb.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), nullable=False, unique=True)
    users = db.relationship('User', backref='role', lazy=True)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    date_of_birth = db.Column(db.Date, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), nullable=False)
    is_active = db.Column(db.Integer, default=1)
    is_suspended = db.Column(db.Integer, default=0)
    failed_attempts = db.Column(db.Integer, default=0)
    account_created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_expiry_date = db.Column(db.DateTime)
    profile_picture = db.Column(db.LargeBinary)

    def get_id(self):
        return str(self.user_id)


class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    history_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    attempt_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    username_attempted = db.Column(db.String(100), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Integer, nullable=False)


class UserSuspension(db.Model):
    __tablename__ = 'user_suspensions'
    suspension_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(255))


class PasswordReset(db.Model):
    __tablename__ = 'password_resets'
    reset_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    reset_token = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Integer, default=0)


class UserRequest(db.Model):
    __tablename__ = 'user_requests'
    request_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255))
    date_of_birth = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="PENDING")
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    reviewed_at = db.Column(db.DateTime)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.match(r'^[a-zA-Z]', password):
        return False, "Password must start with a letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"


def check_password_history(user_id, new_password):
    history = PasswordHistory.query.filter_by(user_id=user_id).all()
    for record in history:
        if check_password_hash(record.password_hash, new_password):
            return False
    return True


def generate_username(first_name, last_name):
    now = datetime.now()
    base = f"{first_name[0].lower()}{last_name.lower()}{now.strftime('%m%y')}"
    username = base
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base}{counter}"
        counter += 1
    return username


def check_suspension(user):
    today = datetime.now().date()
    return UserSuspension.query.filter(
        UserSuspension.user_id == user.user_id,
        UserSuspension.start_date <= today,
        UserSuspension.end_date >= today
    ).first() is not None


def check_password_expiry(user):
    if user.password_expiry_date:
        days = (user.password_expiry_date - datetime.now()).days
        if 0 <= days <= 3:
            return True, days
    return False, None



@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user:
            if check_suspension(user):
                flash("Your account is currently suspended", "error")
                return redirect(url_for("login"))
            if not user.is_active:
                flash("Your account is inactive. Please contact administrator", "error")
                return redirect(url_for("login"))
            if user.failed_attempts >= 3:
                user.is_suspended = 1
                db.session.commit()
                flash("Account suspended due to multiple failed login attempts", "error")
                return redirect(url_for("login"))
            if check_password_hash(user.password_hash, password):
                user.failed_attempts = 0
                db.session.commit()
                db.session.add(LoginAttempt(user_id=user.user_id, username_attempted=username, success=1))
                db.session.commit()
                expiring, days = check_password_expiry(user)
                if expiring:
                    flash(f"Your password will expire in {days} days.", "warning")
                login_user(user)
                return redirect(url_for("dashboard"))
            else:
                user.failed_attempts += 1
                db.session.commit()
                db.session.add(LoginAttempt(user_id=user.user_id, username_attempted=username, success=0))
                db.session.commit()
                flash(f"Invalid password. {3 - user.failed_attempts} attempts remaining", "error")
        else:
            db.session.add(LoginAttempt(username_attempted=username, success=0))
            db.session.commit()
            flash("Invalid username or password", "error")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@app.route("/register-request", methods=["GET", "POST"])
def register_request():
    if request.method == "POST":
        new_request = UserRequest(
            first_name=request.form.get("first_name"),
            last_name=request.form.get("last_name"),
            address=request.form.get("address"),
            date_of_birth=datetime.strptime(request.form.get("date_of_birth"), '%Y-%m-%d').date(),
            email=request.form.get("email")
        )
        db.session.add(new_request)
        db.session.commit()
        flash("Your request has been submitted. Administrator will review it.", "success")
        return redirect(url_for("home"))
    return render_template("register_request.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        user = User.query.filter_by(email=email, username=username).first()
        if user:
            token = secrets.token_urlsafe(32)
            db.session.add(PasswordReset(
                user_id=user.user_id,
                reset_token=token,
                expires_at=datetime.now() + timedelta(hours=24)
            ))
            db.session.commit()
            flash("Password reset link generated.", "success")
            return redirect(url_for("reset_password", token=token))
        flash("Invalid email or username", "error")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset = PasswordReset.query.filter_by(reset_token=token, used=0).first()
    if not reset or reset.expires_at < datetime.now():
        flash("Invalid or expired reset token", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        if new_password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("reset_password.html", token=token)
        valid, message = validate_password(new_password)
        if not valid:
            flash(message, "error")
            return render_template("reset_password.html", token=token)
        if not check_password_history(reset.user_id, new_password):
            flash("Password was used previously.", "error")
            return render_template("reset_password.html", token=token)
        user = User.query.get(reset.user_id)
        db.session.add(PasswordHistory(user_id=user.user_id, password_hash=user.password_hash))
        user.password_hash = generate_password_hash(new_password)
        user.password_expiry_date = datetime.now() + timedelta(days=90)
        user.failed_attempts = 0
        user.is_suspended = 0
        reset.used = 1
        db.session.commit()
        flash("Password reset successfully", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)



@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    return render_template("admin_users.html", users=User.query.all())


@app.route("/admin/requests")
@login_required
def admin_requests():
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    reqs = UserRequest.query.filter_by(status='PENDING').all()
    return render_template("admin_requests.html", requests=reqs)


@app.route("/admin/approve-request/<int:request_id>", methods=["POST"])
@login_required
def approve_request(request_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    user_request = UserRequest.query.get_or_404(request_id)
    role_id = int(request.form.get("role_id"))
    username = generate_username(user_request.first_name, user_request.last_name)
    default_password = "Welcome1!"
    new_user = User(
        username=username,
        password_hash=generate_password_hash(default_password),
        email=user_request.email,
        first_name=user_request.first_name,
        last_name=user_request.last_name,
        address=user_request.address,
        date_of_birth=user_request.date_of_birth,
        role_id=role_id,
        password_expiry_date=datetime.now() + timedelta(days=90)
    )
    db.session.add(new_user)
    user_request.status = 'APPROVED'
    user_request.reviewed_by = current_user.user_id
    user_request.reviewed_at = datetime.now()
    db.session.commit()
    flash(f"User approved. Username: {username}, Default password: {default_password}", "success")
    return redirect(url_for("admin_requests"))


@app.route("/admin/reject-request/<int:request_id>", methods=["POST"])
@login_required
def reject_request(request_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    user_request = UserRequest.query.get_or_404(request_id)
    user_request.status = 'REJECTED'
    user_request.reviewed_by = current_user.user_id
    user_request.reviewed_at = datetime.now()
    db.session.commit()
    flash("Request rejected", "success")
    return redirect(url_for("admin_requests"))


@app.route("/admin/create-user", methods=["GET", "POST"])
@login_required
def admin_create_user():
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        address = request.form.get("address")
        dob = datetime.strptime(request.form.get("date_of_birth"), '%Y-%m-%d').date()
        role_id = int(request.form.get("role_id"))
        password = request.form.get("password")
        valid, message = validate_password(password)
        if not valid:
            flash(message, "error")
            return render_template("admin_create_user.html", roles=Role.query.all())
        username = generate_username(first_name, last_name)
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            first_name=first_name,
            last_name=last_name,
            address=address,
            date_of_birth=dob,
            role_id=role_id,
            password_expiry_date=datetime.now() + timedelta(days=90)
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f"User created. Username: {username}", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin_create_user.html", roles=Role.query.all())


@app.route("/admin/edit-user/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_edit_user(user_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        user.first_name = request.form.get("first_name")
        user.last_name = request.form.get("last_name")
        user.email = request.form.get("email")
        user.address = request.form.get("address")
        user.role_id = int(request.form.get("role_id"))
        user.is_active = int(request.form.get("is_active"))
        db.session.commit()
        flash("User updated successfully", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin_edit_user.html", user=user, roles=Role.query.all())


@app.route("/admin/suspend-user/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_suspend_user(user_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        suspension = UserSuspension(
            user_id=user_id,
            start_date=datetime.strptime(request.form.get("start_date"), '%Y-%m-%d').date(),
            end_date=datetime.strptime(request.form.get("end_date"), '%Y-%m-%d').date(),
            reason=request.form.get("reason")
        )
        db.session.add(suspension)
        db.session.commit()
        flash("User suspended successfully", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin_suspend_user.html", user=user)


@app.route("/admin/expired-passwords")
@login_required
def admin_expired_passwords():
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    expired_users = User.query.filter(User.password_expiry_date < datetime.now()).all()
    return render_template("admin_expired_passwords.html", users=expired_users)


@app.route("/admin/send-email/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_send_email(user_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        flash(f"Email sent to {user.email}", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin_send_email.html", user=user)


class Account(db.Model):
    __tablename__ = 'accounts'

    account_id      = db.Column(db.Integer, primary_key=True)
    account_name    = db.Column(db.String(150), nullable=False, unique=True)
    account_number  = db.Column(db.String(20),  nullable=False, unique=True)
    description     = db.Column(db.Text)
    normal_side     = db.Column(db.String(6),   nullable=False)          # 'Debit' | 'Credit'
    category        = db.Column(db.String(20),  nullable=False)          # derived from account_number prefix
    subcategory     = db.Column(db.String(50))
    initial_balance = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    debit_total     = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    credit_total    = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    current_balance = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    created_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    display_order   = db.Column(db.Integer, default=0)
    statement       = db.Column(db.String(10))                           # 'BS' | 'IS' | 'RE'
    comment         = db.Column(db.Text)
    is_active       = db.Column(db.Integer, nullable=False, default=1)   # 1=active, 0=inactive

    creator = db.relationship('User', backref='accounts_created')


class AccountEventLog(db.Model):
    __tablename__ = 'account_event_log'

    log_id       = db.Column(db.Integer, primary_key=True)
    account_id   = db.Column(db.Integer, db.ForeignKey('accounts.account_id'), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.user_id'),    nullable=False)
    timestamp    = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    action       = db.Column(db.String(20), nullable=False)   # 'CREATE' | 'UPDATE' | 'DEACTIVATE'
    before_image = db.Column(db.Text)                         # JSON string; NULL for CREATE
    after_image  = db.Column(db.Text, nullable=False)         # JSON string

    account = db.relationship('Account', backref='event_logs')
    user    = db.relationship('User',    backref='account_events')


# ── Sprint 3 Models ──────────────────────────────────────────────────────────

class ErrorMessage(db.Model):
    """Req 37 – error messages stored in DB."""
    __tablename__ = 'error_messages'
    error_id   = db.Column(db.Integer, primary_key=True)
    error_code = db.Column(db.String(50), nullable=False, unique=True)
    message    = db.Column(db.String(500), nullable=False)


class JournalEntry(db.Model):
    __tablename__ = 'journal_entries'
    entry_id    = db.Column(db.Integer, primary_key=True)
    date        = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text)
    status      = db.Column(db.String(20), nullable=False, default='PENDING')  # PENDING | APPROVED | REJECTED
    entry_type  = db.Column(db.String(20), nullable=False, default='REGULAR')  # REGULAR | ADJUSTING
    created_by  = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    created_at  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    reviewed_at = db.Column(db.DateTime)
    comment     = db.Column(db.Text)   # rejection reason

    creator  = db.relationship('User', foreign_keys=[created_by], backref='journal_entries_created')
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref='journal_entries_reviewed')
    lines    = db.relationship('JournalEntryLine', backref='entry', cascade='all, delete-orphan')
    attachments = db.relationship('JournalAttachment', backref='entry', cascade='all, delete-orphan')


class JournalEntryLine(db.Model):
    __tablename__ = 'journal_entry_lines'
    line_id      = db.Column(db.Integer, primary_key=True)
    entry_id     = db.Column(db.Integer, db.ForeignKey('journal_entries.entry_id'), nullable=False)
    account_id   = db.Column(db.Integer, db.ForeignKey('accounts.account_id'), nullable=False)
    debit        = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    credit       = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    line_order   = db.Column(db.Integer, default=0)  # debits first (req 20)

    account = db.relationship('Account', backref='journal_lines')


class JournalAttachment(db.Model):
    __tablename__ = 'journal_attachments'
    attachment_id = db.Column(db.Integer, primary_key=True)
    entry_id      = db.Column(db.Integer, db.ForeignKey('journal_entries.entry_id'), nullable=False)
    filename      = db.Column(db.String(255), nullable=False)
    stored_name   = db.Column(db.String(255), nullable=False)
    uploaded_at   = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    """Req 40 – manager notification on journal submission."""
    __tablename__ = 'notifications'
    notif_id   = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    message    = db.Column(db.String(500), nullable=False)
    is_read    = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    link       = db.Column(db.String(255))

    user = db.relationship('User', backref='notifications')


# Helpers

PREFIX_TO_CATEGORY = {
    '1': 'Asset',
    '2': 'Liability',
    '3': 'Equity',
    '4': 'Revenue',
    '5': 'Expense',
}


def derive_category(account_number: str):
    """Return the account category based on the leading digit, or None for invalid input."""
    try:
        first = str(account_number)[0]
    except (IndexError, TypeError):
        return None
    return PREFIX_TO_CATEGORY.get(first)


@app.template_filter('currency')
def format_currency(value):
    """Format a numeric value to two decimal places with comma-separated thousands."""
    try:
        return f"{float(value):,.2f}"
    except (TypeError, ValueError):
        return "0.00"


def account_to_dict(account: Account) -> dict:
    """Serialize all Account fields to a plain dict for JSON snapshots."""
    return {
        'account_id':       account.account_id,
        'account_name':     account.account_name,
        'account_number':   account.account_number,
        'description':      account.description,
        'normal_side':      account.normal_side,
        'category':         account.category,
        'subcategory':      account.subcategory,
        'initial_balance':  float(account.initial_balance) if account.initial_balance is not None else None,
        'debit_total':      float(account.debit_total)     if account.debit_total     is not None else None,
        'credit_total':     float(account.credit_total)    if account.credit_total    is not None else None,
        'current_balance':  float(account.current_balance) if account.current_balance is not None else None,
        'created_at':       account.created_at.isoformat() if account.created_at      is not None else None,
        'creator_user_id':  account.creator_user_id,
        'display_order':    account.display_order,
        'statement':        account.statement,
        'comment':          account.comment,
        'is_active':        account.is_active,
    }


def log_event(action: str, account: Account, before_snapshot: dict = None):
    """Insert an AccountEventLog row. Caller is responsible for db.session.commit()."""
    after = account_to_dict(account)
    entry = AccountEventLog(
        account_id=account.account_id,
        user_id=current_user.user_id,
        action=action,
        before_image=json.dumps(before_snapshot) if before_snapshot else None,
        after_image=json.dumps(after),
    )
    db.session.add(entry)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_error(code):
    """Fetch error message text from DB by code."""
    err = ErrorMessage.query.filter_by(error_code=code).first()
    return err.message if err else code


def notify_managers(message, link=None):
    """Create a notification for all manager users."""
    managers = User.query.join(Role).filter(Role.role_name == 'ROLE_MANAGER').all()
    for mgr in managers:
        db.session.add(Notification(user_id=mgr.user_id, message=message, link=link))


def post_entry_to_ledger(entry: JournalEntry):
    """Update account balances when a journal entry is approved."""
    for line in entry.lines:
        acct = line.account
        acct.debit_total  = float(acct.debit_total)  + float(line.debit)
        acct.credit_total = float(acct.credit_total) + float(line.credit)
        if acct.normal_side == 'Debit':
            acct.current_balance = float(acct.initial_balance) + float(acct.debit_total) - float(acct.credit_total)
        else:
            acct.current_balance = float(acct.initial_balance) + float(acct.credit_total) - float(acct.debit_total)


@app.route("/accounts")
@login_required
def accounts():
    query = Account.query

    search = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip()
    subcategory = request.args.get('subcategory', '').strip()
    normal_side = request.args.get('normal_side', '').strip()
    statement = request.args.get('statement', '').strip()

    if search:
        query = query.filter(
            db.or_(
                Account.account_number.ilike(f'%{search}%'),
                Account.account_name.ilike(f'%{search}%')
            )
        )
    if category:
        query = query.filter(Account.category == category)
    if subcategory:
        query = query.filter(Account.subcategory == subcategory)
    if normal_side:
        query = query.filter(Account.normal_side == normal_side)
    if statement:
        query = query.filter(Account.statement == statement)

    accounts_list = query.order_by(Account.account_number.asc()).all()

    return render_template(
        'chart_of_accounts.html',
        accounts=accounts_list,
        search=search,
        category=category,
        subcategory=subcategory,
        normal_side=normal_side,
        statement=statement,
    )


@app.route("/accounts/add", methods=["GET", "POST"])
@login_required
def accounts_add():
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied.", "error")
        return redirect(url_for('accounts'))

    if request.method == "POST":
        account_name = request.form.get('account_name', '').strip()
        account_number = request.form.get('account_number', '').strip()
        normal_side = request.form.get('normal_side', '').strip()
        initial_balance = request.form.get('initial_balance', '').strip()
        description = request.form.get('description', '').strip()
        subcategory = request.form.get('subcategory', '').strip()
        display_order = request.form.get('display_order', '').strip()
        statement = request.form.get('statement', '').strip()
        comment = request.form.get('comment', '').strip()
        created_at_str = request.form.get('created_at', '').strip()

        # Required field validation
        if not account_name:
            flash("Account name is required.", "error")
            return render_template('account_add.html')
        if not account_number:
            flash("Account number is required.", "error")
            return render_template('account_add.html')
        if not normal_side:
            flash("Normal side is required.", "error")
            return render_template('account_add.html')
        if not initial_balance:
            flash("Initial balance is required.", "error")
            return render_template('account_add.html')
        # Account number must be digits only
        if not account_number.isdigit():
            flash("Account number must contain digits only.", "error")
            return render_template('account_add.html')

        # Leading digit must be 1-5
        if account_number[0] not in {'1', '2', '3', '4', '5'}:
            flash("Account number must start with 1, 2, 3, 4, or 5.", "error")
            return render_template('account_add.html')

        # Parse initial balance
        try:
            initial_balance_val = round(float(initial_balance), 2)
        except ValueError:
            flash("Initial balance must be a valid number.", "error")
            return render_template('account_add.html')

        # Uniqueness checks
        if Account.query.filter_by(account_number=account_number).first():
            flash(f"An account with number '{account_number}' already exists.", "error")
            return render_template('account_add.html')
        if Account.query.filter_by(account_name=account_name).first():
            flash(f"An account with name '{account_name}' already exists.", "error")
            return render_template('account_add.html')

        category = derive_category(account_number)
        # Parse user-supplied created_at or fall back to now
        try:
            created_at_val = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M') if created_at_str else datetime.utcnow()
        except ValueError:
            created_at_val = datetime.utcnow()

        account = Account(
            account_name=account_name,
            account_number=account_number,
            description=description or None,
            normal_side=normal_side,
            category=category,
            subcategory=subcategory or None,
            initial_balance=initial_balance_val,
            current_balance=initial_balance_val,
            created_at=created_at_val,
            creator_user_id=current_user.user_id,
            display_order=int(display_order) if display_order.isdigit() else 0,
            statement=statement or None,
            comment=comment or None,
        )

        try:
            db.session.add(account)
            db.session.flush()
            log_event('CREATE', account)
            db.session.commit()
            flash("Account created successfully.", "success")
            return redirect(url_for('accounts'))
        except SQLAlchemyError:
            db.session.rollback()
            flash("A database error occurred. Please try again.", "danger")

    return render_template('account_add.html')


@app.route("/accounts/event-log")
@login_required
def accounts_event_log():
    logs = AccountEventLog.query.order_by(AccountEventLog.timestamp.desc()).all()
    return render_template('account_event_log.html', logs=logs)


@app.route("/accounts/<int:account_id>")
@login_required
def account_detail(account_id):
    account = Account.query.get_or_404(account_id)
    return render_template('account_detail.html', account=account)


@app.route("/accounts/<int:account_id>/edit", methods=["GET", "POST"])
@login_required
def account_edit(account_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied.", "error")
        return redirect(url_for('accounts'))

    account = Account.query.get_or_404(account_id)

    if request.method == "POST":
        account_name = request.form.get('account_name', '').strip()
        account_number = request.form.get('account_number', '').strip()
        normal_side = request.form.get('normal_side', '').strip()
        initial_balance = request.form.get('initial_balance', '').strip()
        description = request.form.get('description', '').strip()
        subcategory = request.form.get('subcategory', '').strip()
        display_order = request.form.get('display_order', '').strip()
        statement = request.form.get('statement', '').strip()
        comment = request.form.get('comment', '').strip()

        # Required field validation
        if not account_name:
            flash("Account name is required.", "error")
            return render_template('account_edit.html', account=account)
        if not account_number:
            flash("Account number is required.", "error")
            return render_template('account_edit.html', account=account)
        if not normal_side:
            flash("Normal side is required.", "error")
            return render_template('account_edit.html', account=account)
        if not initial_balance:
            flash("Initial balance is required.", "error")
            return render_template('account_edit.html', account=account)

        # Account number must be digits only
        if not account_number.isdigit():
            flash("Account number must contain digits only.", "error")
            return render_template('account_edit.html', account=account)

        # Leading digit must be 1-5
        if account_number[0] not in {'1', '2', '3', '4', '5'}:
            flash("Account number must start with 1, 2, 3, 4, or 5.", "error")
            return render_template('account_edit.html', account=account)

        # Parse initial balance
        try:
            initial_balance_val = round(float(initial_balance), 2)
        except ValueError:
            flash("Initial balance must be a valid number.", "error")
            return render_template('account_edit.html', account=account)

        # Uniqueness checks (exclude current account)
        dup_number = Account.query.filter(
            Account.account_number == account_number,
            Account.account_id != account_id
        ).first()
        if dup_number:
            flash(f"An account with number '{account_number}' already exists.", "error")
            return render_template('account_edit.html', account=account)

        dup_name = Account.query.filter(
            Account.account_name == account_name,
            Account.account_id != account_id
        ).first()
        if dup_name:
            flash(f"An account with name '{account_name}' already exists.", "error")
            return render_template('account_edit.html', account=account)

        before_snapshot = account_to_dict(account)

        account.account_name = account_name
        account.account_number = account_number
        account.normal_side = normal_side
        account.initial_balance = initial_balance_val
        account.description = description or None
        account.subcategory = subcategory or None
        account.display_order = int(display_order) if display_order.isdigit() else 0
        account.statement = statement or None
        account.comment = comment or None
        account.category = derive_category(account_number)

        try:
            log_event('UPDATE', account, before_snapshot)
            db.session.commit()
            flash("Account updated successfully.", "success")
            return redirect(url_for('account_detail', account_id=account_id))
        except SQLAlchemyError:
            db.session.rollback()
            flash("A database error occurred. Please try again.", "danger")

    return render_template('account_edit.html', account=account)


@app.route("/accounts/<int:account_id>/deactivate", methods=["POST"])
@login_required
def account_deactivate(account_id):
    if current_user.role.role_name != 'ROLE_ADMIN':
        flash("Access denied.", "error")
        return redirect(url_for('accounts'))

    account = Account.query.get_or_404(account_id)

    if float(account.current_balance) != 0:
        flash("Cannot deactivate: account has a non-zero balance.", "error")
        return redirect(url_for('account_detail', account_id=account_id))

    before_snapshot = account_to_dict(account)
    account.is_active = 0

    try:
        log_event('DEACTIVATE', account, before_snapshot)
        db.session.commit()
        flash("Account deactivated.", "success")
    except SQLAlchemyError:
        db.session.rollback()
        flash("A database error occurred. Please try again.", "danger")

    return redirect(url_for('account_detail', account_id=account_id))


@app.route("/accounts/<int:account_id>/ledger")
@login_required
def account_ledger(account_id):
    account = Account.query.get_or_404(account_id)

    # Build query of approved journal lines for this account
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()
    search    = request.args.get('search', '').strip()

    lines_q = (JournalEntryLine.query
               .join(JournalEntry)
               .filter(JournalEntryLine.account_id == account_id,
                       JournalEntry.status == 'APPROVED'))

    if date_from:
        try:
            lines_q = lines_q.filter(JournalEntry.date >= datetime.strptime(date_from, '%Y-%m-%d').date())
        except ValueError:
            pass
    if date_to:
        try:
            lines_q = lines_q.filter(JournalEntry.date <= datetime.strptime(date_to, '%Y-%m-%d').date())
        except ValueError:
            pass
    if search:
        try:
            amt = float(search)
            lines_q = lines_q.filter(
                db.or_(JournalEntryLine.debit == amt, JournalEntryLine.credit == amt))
        except ValueError:
            pass  # amount search only

    lines = lines_q.order_by(JournalEntry.date.asc(), JournalEntryLine.line_id.asc()).all()

    # Compute running balance
    balance = float(account.initial_balance)
    rows = []
    for ln in lines:
        if account.normal_side == 'Debit':
            balance += float(ln.debit) - float(ln.credit)
        else:
            balance += float(ln.credit) - float(ln.debit)
        rows.append({'line': ln, 'balance': balance})

    return render_template('account_ledger.html', account=account, rows=rows,
                           date_from=date_from, date_to=date_to, search=search)


# ── Sprint 3: send email from accounts page ──────────────────────────────────

@app.route("/accounts/send-email", methods=["GET", "POST"])
@login_required
def accounts_send_email():
    role = current_user.role.role_name
    if role not in ('ROLE_ADMIN', 'ROLE_MANAGER', 'ROLE_USER'):
        flash("Access denied.", "error")
        return redirect(url_for('accounts'))

    # Admins can email managers/accountants; accountants/managers can email managers/admins
    if role == 'ROLE_ADMIN':
        recipients = User.query.join(Role).filter(
            Role.role_name.in_(['ROLE_MANAGER', 'ROLE_USER'])).all()
    else:
        recipients = User.query.join(Role).filter(
            Role.role_name.in_(['ROLE_MANAGER', 'ROLE_ADMIN'])).all()

    if request.method == "POST":
        to_user_id = request.form.get('to_user_id')
        subject    = request.form.get('subject', '').strip()
        body       = request.form.get('body', '').strip()
        to_user    = User.query.get(to_user_id)
        if not to_user or not subject or not body:
            flash("All fields are required.", "error")
        else:
            flash(f"Email sent to {to_user.email} ({to_user.first_name} {to_user.last_name}).", "success")
            return redirect(url_for('accounts'))
    return render_template('accounts_send_email.html', recipients=recipients)


# ── Sprint 3: notifications ───────────────────────────────────────────────────

@app.route("/notifications")
@login_required
def notifications():
    notifs = Notification.query.filter_by(user_id=current_user.user_id)\
                               .order_by(Notification.created_at.desc()).all()
    # mark all read
    for n in notifs:
        n.is_read = 1
    db.session.commit()
    return render_template('notifications.html', notifs=notifs)


@app.route("/notifications/count")
@login_required
def notifications_count():
    count = Notification.query.filter_by(user_id=current_user.user_id, is_read=0).count()
    return jsonify({'count': count})


# ── Sprint 3: Journal Entries ─────────────────────────────────────────────────

@app.route("/journal")
@login_required
def journal_list():
    role   = current_user.role.role_name
    status = request.args.get('status', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()
    search    = request.args.get('search', '').strip()

    q = JournalEntry.query

    if status:
        q = q.filter(JournalEntry.status == status)
    if date_from:
        try:
            q = q.filter(JournalEntry.date >= datetime.strptime(date_from, '%Y-%m-%d').date())
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(JournalEntry.date <= datetime.strptime(date_to, '%Y-%m-%d').date())
        except ValueError:
            pass
    if search:
        # search by account name or amount
        try:
            amt = float(search)
            entry_ids = db.session.query(JournalEntryLine.entry_id).filter(
                db.or_(JournalEntryLine.debit == amt, JournalEntryLine.credit == amt)).subquery()
            q = q.filter(JournalEntry.entry_id.in_(entry_ids))
        except ValueError:
            # search by account name
            entry_ids = (db.session.query(JournalEntryLine.entry_id)
                         .join(Account)
                         .filter(Account.account_name.ilike(f'%{search}%'))
                         .subquery())
            q = q.filter(db.or_(
                JournalEntry.entry_id.in_(entry_ids),
                JournalEntry.date.cast(db.String).ilike(f'%{search}%')
            ))

    entries = q.order_by(JournalEntry.created_at.desc()).all()
    return render_template('journal_list.html', entries=entries,
                           status=status, date_from=date_from, date_to=date_to, search=search)


@app.route("/journal/new", methods=["GET", "POST"])
@login_required
def journal_new():
    role = current_user.role.role_name
    if role not in ('ROLE_MANAGER', 'ROLE_USER'):
        flash("Access denied.", "error")
        return redirect(url_for('journal_list'))

    accounts_list = Account.query.filter_by(is_active=1).order_by(Account.account_number).all()

    if request.method == "POST":
        action = request.form.get('action', 'submit')  # 'submit' or 'cancel'
        if action == 'cancel':
            return redirect(url_for('journal_list'))

        date_str    = request.form.get('date', '').strip()
        description = request.form.get('description', '').strip()

        # Collect lines from form
        account_ids = request.form.getlist('account_id[]')
        debits      = request.form.getlist('debit[]')
        credits     = request.form.getlist('credits[]')
        line_types  = request.form.getlist('line_type[]')  # 'debit' | 'credit'

        errors = []

        # Date validation
        try:
            entry_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            errors.append(get_error('INVALID_DATE'))

        # Build line objects
        parsed_lines = []
        total_debit  = 0.0
        total_credit = 0.0
        has_debit    = False
        has_credit   = False

        for i, (aid, d, c, lt) in enumerate(zip(account_ids, debits, credits, line_types)):
            try:
                dval = round(float(d or 0), 2)
                cval = round(float(c or 0), 2)
            except ValueError:
                errors.append(get_error('INVALID_AMOUNT'))
                continue

            if dval < 0 or cval < 0:
                errors.append(get_error('NEGATIVE_AMOUNT'))
                continue

            if dval == 0 and cval == 0:
                errors.append(get_error('ZERO_LINE'))
                continue

            if dval > 0 and cval > 0:
                errors.append(get_error('BOTH_DEBIT_CREDIT'))
                continue

            acct = Account.query.get(aid)
            if not acct or not acct.is_active:
                errors.append(get_error('INVALID_ACCOUNT'))
                continue

            if dval > 0:
                has_debit = True
            if cval > 0:
                has_credit = True

            total_debit  += dval
            total_credit += cval
            parsed_lines.append({'account_id': int(aid), 'debit': dval, 'credit': cval,
                                  'line_type': lt, 'order': i})

        if not has_debit:
            errors.append(get_error('NO_DEBIT'))
        if not has_credit:
            errors.append(get_error('NO_CREDIT'))
        if abs(total_debit - total_credit) > 0.005:
            errors.append(get_error('UNBALANCED_ENTRY').format(
                debit=f'{total_debit:,.2f}', credit=f'{total_credit:,.2f}'))

        if errors:
            return render_template('journal_new.html', accounts=accounts_list,
                                   errors=errors, form=request.form)

        # Sort: debits first (req 20)
        parsed_lines.sort(key=lambda x: (0 if x['line_type'] == 'debit' else 1, x['order']))

        entry = JournalEntry(
            date=entry_date,
            description=description or None,
            status='PENDING',
            created_by=current_user.user_id,
        )
        db.session.add(entry)
        db.session.flush()

        for idx, pl in enumerate(parsed_lines):
            db.session.add(JournalEntryLine(
                entry_id=entry.entry_id,
                account_id=pl['account_id'],
                debit=pl['debit'],
                credit=pl['credit'],
                line_order=idx,
            ))

        # Handle file attachments (req 22)
        files = request.files.getlist('attachments')
        for f in files:
            if f and f.filename and allowed_file(f.filename):
                safe = secure_filename(f.filename)
                stored = f"{entry.entry_id}_{secrets.token_hex(6)}_{safe}"
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], stored))
                db.session.add(JournalAttachment(
                    entry_id=entry.entry_id, filename=safe, stored_name=stored))

        # Notify managers (req 40)
        notify_managers(
            f"Journal entry #{entry.entry_id} submitted by {current_user.username} for approval.",
            link=url_for('journal_detail', entry_id=entry.entry_id))

        db.session.commit()
        flash("Journal entry submitted for approval.", "success")
        return redirect(url_for('journal_list'))

    return render_template('journal_new.html', accounts=accounts_list, errors=[], form={})


@app.route("/journal/<int:entry_id>")
@login_required
def journal_detail(entry_id):
    entry = JournalEntry.query.get_or_404(entry_id)
    return render_template('journal_detail.html', entry=entry)


@app.route("/journal/<int:entry_id>/review", methods=["GET", "POST"])
@login_required
def journal_review(entry_id):
    if current_user.role.role_name != 'ROLE_MANAGER':
        flash("Access denied.", "error")
        return redirect(url_for('journal_list'))

    entry = JournalEntry.query.get_or_404(entry_id)
    if entry.status != 'PENDING':
        flash("This entry has already been reviewed.", "warning")
        return redirect(url_for('journal_detail', entry_id=entry_id))

    if request.method == "POST":
        decision = request.form.get('decision')  # 'APPROVED' | 'REJECTED'
        comment  = request.form.get('comment', '').strip()

        if decision == 'REJECTED' and not comment:
            flash("A rejection reason is required.", "error")
            return render_template('journal_review.html', entry=entry)

        entry.status      = decision
        entry.reviewed_by = current_user.user_id
        entry.reviewed_at = datetime.utcnow()
        entry.comment     = comment or None

        if decision == 'APPROVED':
            post_entry_to_ledger(entry)

        db.session.commit()
        flash(f"Journal entry {decision.lower()}.", "success")
        return redirect(url_for('journal_list'))

    return render_template('journal_review.html', entry=entry)


@app.route("/journal/<int:entry_id>/attachment/<int:att_id>")
@login_required
def journal_attachment(entry_id, att_id):
    att = JournalAttachment.query.get_or_404(att_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], att.stored_name,
                               as_attachment=True, download_name=att.filename)


# ── Sprint 4: Adjusting Entries ───────────────────────────────────────────────

@app.route("/adjusting")
@login_required
def adjusting_list():
    status    = request.args.get('status', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()
    search    = request.args.get('search', '').strip()

    q = JournalEntry.query.filter(JournalEntry.entry_type == 'ADJUSTING')

    if status:
        q = q.filter(JournalEntry.status == status)
    if date_from:
        try:
            q = q.filter(JournalEntry.date >= datetime.strptime(date_from, '%Y-%m-%d').date())
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(JournalEntry.date <= datetime.strptime(date_to, '%Y-%m-%d').date())
        except ValueError:
            pass
    if search:
        try:
            amt = float(search)
            eids = db.session.query(JournalEntryLine.entry_id).filter(
                db.or_(JournalEntryLine.debit == amt, JournalEntryLine.credit == amt)).subquery()
            q = q.filter(JournalEntry.entry_id.in_(eids))
        except ValueError:
            eids = (db.session.query(JournalEntryLine.entry_id)
                    .join(Account)
                    .filter(Account.account_name.ilike(f'%{search}%'))
                    .subquery())
            q = q.filter(db.or_(
                JournalEntry.entry_id.in_(eids),
                JournalEntry.date.cast(db.String).ilike(f'%{search}%')
            ))

    entries = q.order_by(JournalEntry.created_at.desc()).all()
    return render_template('adjusting_list.html', entries=entries,
                           status=status, date_from=date_from, date_to=date_to, search=search)


@app.route("/adjusting/new", methods=["GET", "POST"])
@login_required
def adjusting_new():
    role = current_user.role.role_name
    if role not in ('ROLE_MANAGER', 'ROLE_USER'):
        flash("Access denied.", "error")
        return redirect(url_for('adjusting_list'))

    accounts_list = Account.query.filter_by(is_active=1).order_by(Account.account_number).all()

    if request.method == "POST":
        action = request.form.get('action', 'submit')
        if action == 'cancel':
            return redirect(url_for('adjusting_list'))

        date_str    = request.form.get('date', '').strip()
        description = request.form.get('description', '').strip()
        account_ids = request.form.getlist('account_id[]')
        debits      = request.form.getlist('debit[]')
        credits     = request.form.getlist('credits[]')
        line_types  = request.form.getlist('line_type[]')

        errors = []
        try:
            entry_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            errors.append(get_error('INVALID_DATE'))
            entry_date = None

        parsed_lines = []
        total_debit = total_credit = 0.0
        has_debit = has_credit = False

        for i, (aid, d, c, lt) in enumerate(zip(account_ids, debits, credits, line_types)):
            try:
                dval = round(float(d or 0), 2)
                cval = round(float(c or 0), 2)
            except ValueError:
                errors.append(get_error('INVALID_AMOUNT')); continue
            if dval < 0 or cval < 0:
                errors.append(get_error('NEGATIVE_AMOUNT')); continue
            if dval == 0 and cval == 0:
                errors.append(get_error('ZERO_LINE')); continue
            if dval > 0 and cval > 0:
                errors.append(get_error('BOTH_DEBIT_CREDIT')); continue
            acct = Account.query.get(aid)
            if not acct or not acct.is_active:
                errors.append(get_error('INVALID_ACCOUNT')); continue
            if dval > 0: has_debit = True
            if cval > 0: has_credit = True
            total_debit += dval; total_credit += cval
            parsed_lines.append({'account_id': int(aid), 'debit': dval, 'credit': cval,
                                  'line_type': lt, 'order': i})

        if not has_debit:  errors.append(get_error('NO_DEBIT'))
        if not has_credit: errors.append(get_error('NO_CREDIT'))
        if abs(total_debit - total_credit) > 0.005:
            errors.append(get_error('UNBALANCED_ENTRY').format(
                debit=f'{total_debit:,.2f}', credit=f'{total_credit:,.2f}'))

        if errors:
            return render_template('adjusting_new.html', accounts=accounts_list,
                                   errors=errors, form=request.form)

        parsed_lines.sort(key=lambda x: (0 if x['line_type'] == 'debit' else 1, x['order']))

        entry = JournalEntry(
            date=entry_date,
            description=description or None,
            status='PENDING',
            entry_type='ADJUSTING',
            created_by=current_user.user_id,
        )
        db.session.add(entry)
        db.session.flush()

        for idx, pl in enumerate(parsed_lines):
            db.session.add(JournalEntryLine(
                entry_id=entry.entry_id,
                account_id=pl['account_id'],
                debit=pl['debit'],
                credit=pl['credit'],
                line_order=idx,
            ))

        files = request.files.getlist('attachments')
        for f in files:
            if f and f.filename and allowed_file(f.filename):
                safe = secure_filename(f.filename)
                stored = f"{entry.entry_id}_{secrets.token_hex(6)}_{safe}"
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], stored))
                db.session.add(JournalAttachment(
                    entry_id=entry.entry_id, filename=safe, stored_name=stored))

        notify_managers(
            f"Adjusting entry #{entry.entry_id} submitted by {current_user.username} for approval.",
            link=url_for('adjusting_detail', entry_id=entry.entry_id))

        db.session.commit()
        flash("Adjusting entry submitted for approval.", "success")
        return redirect(url_for('adjusting_list'))

    return render_template('adjusting_new.html', accounts=accounts_list, errors=[], form={})


@app.route("/adjusting/<int:entry_id>")
@login_required
def adjusting_detail(entry_id):
    entry = JournalEntry.query.filter_by(entry_id=entry_id, entry_type='ADJUSTING').first_or_404()
    return render_template('adjusting_detail.html', entry=entry)


@app.route("/adjusting/<int:entry_id>/review", methods=["GET", "POST"])
@login_required
def adjusting_review(entry_id):
    if current_user.role.role_name != 'ROLE_MANAGER':
        flash("Access denied.", "error")
        return redirect(url_for('adjusting_list'))

    entry = JournalEntry.query.filter_by(entry_id=entry_id, entry_type='ADJUSTING').first_or_404()
    if entry.status != 'PENDING':
        flash("This entry has already been reviewed.", "warning")
        return redirect(url_for('adjusting_detail', entry_id=entry_id))

    if request.method == "POST":
        decision = request.form.get('decision')
        comment  = request.form.get('comment', '').strip()
        if decision == 'REJECTED' and not comment:
            flash("A rejection reason is required.", "error")
            return render_template('adjusting_review.html', entry=entry)
        entry.status      = decision
        entry.reviewed_by = current_user.user_id
        entry.reviewed_at = datetime.utcnow()
        entry.comment     = comment or None
        if decision == 'APPROVED':
            post_entry_to_ledger(entry)
        db.session.commit()
        flash(f"Adjusting entry {decision.lower()}.", "success")
        return redirect(url_for('adjusting_list'))

    return render_template('adjusting_review.html', entry=entry)


# ── Sprint 4: Financial Reports ───────────────────────────────────────────────

def _get_report_date(default_today=True):
    """Parse as_of date from request args."""
    as_of = request.args.get('as_of', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to   = request.args.get('date_to', '').strip()
    try:
        as_of_date = datetime.strptime(as_of, '%Y-%m-%d').date() if as_of else datetime.utcnow().date()
    except ValueError:
        as_of_date = datetime.utcnow().date()
    try:
        df = datetime.strptime(date_from, '%Y-%m-%d').date() if date_from else None
    except ValueError:
        df = None
    try:
        dt = datetime.strptime(date_to, '%Y-%m-%d').date() if date_to else None
    except ValueError:
        dt = None
    return as_of_date, df, dt


def _account_balance_as_of(account, as_of_date):
    """Compute balance for an account considering only approved entries up to as_of_date."""
    lines = (JournalEntryLine.query
             .join(JournalEntry)
             .filter(JournalEntryLine.account_id == account.account_id,
                     JournalEntry.status == 'APPROVED',
                     JournalEntry.date <= as_of_date)
             .all())
    total_d = sum(float(l.debit)  for l in lines)
    total_c = sum(float(l.credit) for l in lines)
    init    = float(account.initial_balance)
    if account.normal_side == 'Debit':
        return init + total_d - total_c
    else:
        return init + total_c - total_d


def _account_balance_range(account, date_from, date_to):
    """Net activity for an account within a date range (approved entries only)."""
    q = (JournalEntryLine.query
         .join(JournalEntry)
         .filter(JournalEntryLine.account_id == account.account_id,
                 JournalEntry.status == 'APPROVED'))
    if date_from:
        q = q.filter(JournalEntry.date >= date_from)
    if date_to:
        q = q.filter(JournalEntry.date <= date_to)
    lines = q.all()
    total_d = sum(float(l.debit)  for l in lines)
    total_c = sum(float(l.credit) for l in lines)
    if account.normal_side == 'Debit':
        return total_d - total_c
    else:
        return total_c - total_d


@app.route("/reports/trial-balance")
@login_required
def report_trial_balance():
    if current_user.role.role_name != 'ROLE_MANAGER':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    as_of_date, _, _ = _get_report_date()
    accounts_all = Account.query.order_by(Account.account_number).all()

    rows = []
    total_debit = total_credit = 0.0
    for acct in accounts_all:
        bal = _account_balance_as_of(acct, as_of_date)
        if acct.normal_side == 'Debit':
            d, c = (bal if bal >= 0 else 0), (abs(bal) if bal < 0 else 0)
        else:
            d, c = (abs(bal) if bal < 0 else 0), (bal if bal >= 0 else 0)
        total_debit  += d
        total_credit += c
        rows.append({'account': acct, 'debit': d, 'credit': c})

    return render_template('report_trial_balance.html', rows=rows,
                           total_debit=total_debit, total_credit=total_credit,
                           as_of=as_of_date)


@app.route("/reports/income-statement")
@login_required
def report_income_statement():
    if current_user.role.role_name != 'ROLE_MANAGER':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    as_of_date, date_from, date_to = _get_report_date()
    if not date_to:
        date_to = as_of_date

    revenues = Account.query.filter_by(category='Revenue', is_active=1).order_by(Account.account_number).all()
    expenses = Account.query.filter_by(category='Expense', is_active=1).order_by(Account.account_number).all()

    rev_rows = [{'account': a, 'amount': _account_balance_range(a, date_from, date_to)} for a in revenues]
    exp_rows = [{'account': a, 'amount': _account_balance_range(a, date_from, date_to)} for a in expenses]

    total_revenue = sum(r['amount'] for r in rev_rows)
    total_expense = sum(r['amount'] for r in exp_rows)
    net_income    = total_revenue - total_expense

    return render_template('report_income_statement.html',
                           rev_rows=rev_rows, exp_rows=exp_rows,
                           total_revenue=total_revenue, total_expense=total_expense,
                           net_income=net_income,
                           date_from=date_from, date_to=date_to)


@app.route("/reports/balance-sheet")
@login_required
def report_balance_sheet():
    if current_user.role.role_name != 'ROLE_MANAGER':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    as_of_date, _, _ = _get_report_date()

    assets      = Account.query.filter_by(category='Asset',     is_active=1).order_by(Account.account_number).all()
    liabilities = Account.query.filter_by(category='Liability', is_active=1).order_by(Account.account_number).all()
    equity      = Account.query.filter_by(category='Equity',    is_active=1).order_by(Account.account_number).all()

    asset_rows = [{'account': a, 'amount': _account_balance_as_of(a, as_of_date)} for a in assets]
    liab_rows  = [{'account': a, 'amount': _account_balance_as_of(a, as_of_date)} for a in liabilities]
    eq_rows    = [{'account': a, 'amount': _account_balance_as_of(a, as_of_date)} for a in equity]

    total_assets = sum(r['amount'] for r in asset_rows)
    total_liab   = sum(r['amount'] for r in liab_rows)
    total_equity = sum(r['amount'] for r in eq_rows)

    return render_template('report_balance_sheet.html',
                           asset_rows=asset_rows, liab_rows=liab_rows, eq_rows=eq_rows,
                           total_assets=total_assets, total_liab=total_liab, total_equity=total_equity,
                           as_of=as_of_date)


@app.route("/reports/retained-earnings")
@login_required
def report_retained_earnings():
    if current_user.role.role_name != 'ROLE_MANAGER':
        flash("Access denied.", "error")
        return redirect(url_for('dashboard'))

    as_of_date, date_from, date_to = _get_report_date()
    if not date_to:
        date_to = as_of_date

    # Beginning retained earnings = RE accounts balance before date_from
    re_accounts = Account.query.filter_by(category='Equity', is_active=1).order_by(Account.account_number).all()
    re_rows = [{'account': a, 'amount': _account_balance_as_of(a, date_from) if date_from else _account_balance_as_of(a, as_of_date)} for a in re_accounts]
    beginning_re = sum(r['amount'] for r in re_rows)

    # Net income for the period
    revenues = Account.query.filter_by(category='Revenue', is_active=1).all()
    expenses = Account.query.filter_by(category='Expense', is_active=1).all()
    total_rev = sum(_account_balance_range(a, date_from, date_to) for a in revenues)
    total_exp = sum(_account_balance_range(a, date_from, date_to) for a in expenses)
    net_income = total_rev - total_exp

    ending_re = beginning_re + net_income

    return render_template('report_retained_earnings.html',
                           beginning_re=beginning_re, net_income=net_income,
                           ending_re=ending_re,
                           date_from=date_from, date_to=date_to, as_of=as_of_date)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not Role.query.first():
            db.session.add(Role(role_name='ROLE_ADMIN'))
            db.session.add(Role(role_name='ROLE_MANAGER'))
            db.session.add(Role(role_name='ROLE_USER'))
            db.session.commit()
        if not User.query.filter_by(username='admin0325').first():
            admin_role = Role.query.filter_by(role_name='ROLE_ADMIN').first()
            admin = User(
                username='admin0325',
                password_hash=generate_password_hash('Admin123!'),
                email='admin@lockbook.com',
                first_name='Admin',
                last_name='User',
                date_of_birth=datetime(1990, 1, 1).date(),
                role_id=admin_role.role_id,
                password_expiry_date=datetime.now() + timedelta(days=90)
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: admin0325 / Admin123!")
        # Seed error messages (Req 37)
        error_seeds = [
            ('INVALID_DATE',       'Invalid date format. Please use YYYY-MM-DD.'),
            ('INVALID_AMOUNT',     'Amount must be a valid number.'),
            ('NEGATIVE_AMOUNT',    'Amounts cannot be negative.'),
            ('ZERO_LINE',          'Each line must have a non-zero debit or credit amount.'),
            ('BOTH_DEBIT_CREDIT',  'A line cannot have both a debit and a credit amount.'),
            ('INVALID_ACCOUNT',    'One or more selected accounts are invalid or inactive.'),
            ('NO_DEBIT',           'Journal entry must have at least one debit line.'),
            ('NO_CREDIT',          'Journal entry must have at least one credit line.'),
            ('UNBALANCED_ENTRY',   'Total debits ({debit}) do not equal total credits ({credit}). Please correct the amounts.'),
        ]
        for code, msg in error_seeds:
            if not ErrorMessage.query.filter_by(error_code=code).first():
                db.session.add(ErrorMessage(error_code=code, message=msg))
        db.session.commit()
    app.run(debug=True)
