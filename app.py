import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text 
# -----------------------------
# App & DB configuration
# -----------------------------
app = Flask(__name__)

# مفتاح سري للجلسات (في الواقع نحطه في ENV)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# إعداد SQLite
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "todo.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -----------------------------
# Database Models
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    is_done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User", backref=db.backref("tasks", lazy=True))


# -----------------------------
# Helpers
# -----------------------------
def current_user():
    if "user_id" in session:
        return User.query.get(session["user_id"])
    return None


from functools import wraps


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper



# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already exists.", "warning")
            return redirect(url_for("register"))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    user = current_user()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Task title cannot be empty.", "danger")
            return redirect(url_for("dashboard"))

        new_task = Task(title=title, user_id=user.id)
        db.session.add(new_task)
        db.session.commit()
        flash("Task added.", "success")
        return redirect(url_for("dashboard"))

    tasks = Task.query.filter_by(user_id=user.id).all()
    return render_template("dashboard.html", user=user, tasks=tasks)


@app.route("/toggle_task/<int:task_id>", methods=["POST"])
@login_required
def toggle_task(task_id: int):
    user = current_user()
    task = Task.query.filter_by(id=task_id, user_id=user.id).first()
    if not task:
        flash("Task not found.", "danger")
        return redirect(url_for("dashboard"))

    task.is_done = not task.is_done
    db.session.commit()
    flash("Task updated.", "info")
    return redirect(url_for("dashboard"))


# -----------------------------
# مثال ثغرة + الإصلاح (للتقرير)
# -----------------------------
@app.route("/admin/search_insecure")
def search_insecure():
    username = request.args.get("username", "")

    # ❌ ثغرة SQL Injection (ما زالت موجودة، لأننا نركّب SQL كنص)
    raw_sql = f"SELECT id, username FROM user WHERE username = '{username}'"
    result = db.session.execute(text(raw_sql)).fetchall()  # 👈 لفّيناه بـ text()

    return {
        "note": "Insecure endpoint - SQL injection possible (for demo only).",
        "result": [dict(row._mapping) for row in result],
    }



@app.route("/admin/search_secure")
def search_secure():
    username = request.args.get("username", "")

    # ✅ نسخة آمنة باستخدام SQLAlchemy
    users = User.query.filter(User.username == username).all()
    return {
        "note": "Secure search using parameterized query.",
        "result": [{"id": u.id, "username": u.username} for u in users],
    }


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    # ننشئ الجداول مرة وحدة قبل ما يشتغل السيرفر
    with app.app_context():
        db.create_all()

    app.run(debug=True)

