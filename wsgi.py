from datetime import datetime, timedelta

from flask import Flask, request, render_template, redirect, flash, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import os
import pytz

# ####################
# configuration       |
######################
app = Flask(__name__)
app.secret_key = 'mf8Z5cOGwW_sOnaxOzU38oaaQ5zlR8ZXKg_qUL3mBe-6aRPM'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///main.db"

db = SQLAlchemy(app)
crypt = Bcrypt(app)
migrate = Migrate(app=app, db=db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(email=user_id).first()


# Configure the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


# ##########
# Model
# ##########


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    email = db.Column(db.String(255), primary_key=True)
    password = db.Column(db.String(90), nullable=False)
    scheduled_task = db.relationship("Schedule", backref="user", lazy=True)

    def setpassword(self, password:str) -> None:
        self.password = crypt.generate_password_hash(password)

    def verify_password(self, password:str) -> bool:
        return crypt.check_password_hash(self.password, password)

    def __init__(self, email, password):
        self.email = email
        self.setpassword(password)

    def get_id(self):
        return self.email


class Schedule(db.Model):
    __tablename__ = 'schedule'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(225), db.ForeignKey("users.email"), nullable=False)
    image = db.Column(db.String(255), nullable=False)
    scheduleTo = db.Column(db.DateTime, nullable=False)
    date_on = db.Column(db.DateTime, nullable=False)

    text = db.relationship("ImageText", backref="task", lazy=True)

    def __init__(self, user:User, image:str, scheduleTo:datetime):
        self.scheduleTo = scheduleTo
        self.email = user.email
        self.image = image
        self.date_on = datetime.now()

    def isExtracted(self):
        return self.scheduleTo - datetime.now() > timedelta(microseconds=0)


class ImageText(db.Model):
    __tablename__ = "image_text"

    task_id = db.Column(db.Integer, db.ForeignKey("schedule.id"), primary_key=True)
    text = db.Column(db.Text, nullable=False)


# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route("/")
@login_required
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html')


@app.route("/post_user", methods=['POST'])
def post_user():
    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter(User.email==email).first()
    if user is None:
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash(message="Successfully registered", category='success')
        return redirect("login")
    else:
        flash(message="Email already in uses", category="danger")
        return redirect("register")


@app.route('/login', methods=["GET"])
def login():
    return render_template('login.html')


@app.route("/auth", methods=["POST"])
def auth():
    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter(User.email==email).first()
    if user is not None and user.verify_password(password):
        login_user(user)
        flash(message="Successfully Logged in!", category='success')
        return redirect(url_for("index"))
    else:
        flash("Wrong email or password!", 'danger')
        return redirect('login')


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file selected'

        file = request.files['file']

        # Validate the file
        if file.filename == '':
            return 'No file selected'
        if not allowed_file(file.filename):
            return 'Invalid file type'

        # Save the file
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        return 'File uploaded successfully'

    return render_template('upload.html')
