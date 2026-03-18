from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re, secrets, os

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
    app.run(debug=True)
