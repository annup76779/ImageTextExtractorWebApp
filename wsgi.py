import threading
from datetime import datetime, timedelta
from time import sleep

from flask import Flask, request, render_template, redirect, flash, url_for, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import os
import pytz

from textExtractor import extract_text_from_image

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
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


# ##########
# Model
# ##########


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    email = db.Column(db.String(255), primary_key=True)
    password = db.Column(db.String(90), nullable=False)
    scheduled_task = db.relationship("Schedule", backref="user", lazy='dynamic')

    def setpassword(self, password: str) -> None:
        self.password = crypt.generate_password_hash(password)

    def verify_password(self, password: str) -> bool:
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

    def __init__(self, user: User, image: str, scheduleTo: datetime):
        self.scheduleTo = scheduleTo
        self.email = user.email
        self.image = image
        self.date_on = datetime.now(tz=pytz.timezone("Asia/Kolkata"))

    def isExtracted(self):
        return self.scheduleTo - datetime.now() <= timedelta(days=0, seconds=0, microseconds=0)


class ImageText(db.Model):
    __tablename__ = "image_text"

    task_id = db.Column(db.Integer, db.ForeignKey("schedule.id"), primary_key=True)
    text = db.Column(db.Text, nullable=False)

    def __init__(self, task: Schedule, text: str):
        self.task_id = task.id
        self.text = str(text)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route("/")
@login_required
def index():
    return render_template('index.html')


@app.route("/getTasks", methods=["POST"])
@login_required
def get_tasks():
    draw = request.form.get('draw')
    row = int(request.form.get("start", 1))
    rowperpage = int(request.form.get("length", 2))
    tasks = current_user.scheduled_task.paginate(page=row/rowperpage, per_page=rowperpage, error_out=False)
    data = [(
        task.id,
        "<a href='%s' target=_blank>View Image</a>" % ("/static/%s" % task.image,)
        , task.scheduleTo.strftime("%b %d, %Y %H:%M"),
        ImageText.query.get(task.id).text[:40] + ' ' + "<a href='/getText?id=%s' target='_blank'>full text</a>"%task.id \
            if task.isExtracted() and task.text else "-- --",
        task.date_on.strftime("%b %d, %Y %H:%M")
    )
        for task in tasks.items
    ]
    response = {
        "draw": int(draw),
        "recordsTotal": tasks.total,
        "recordsFiltered": tasks.total,
        "aaData": data,
    }

    return jsonify(**response)


@app.route("/getText", methods=["GET"])
@login_required
def getText():
    id_ = request.args.get("id")
    obj = ImageText.query.get(int(id_))
    if obj:
        return obj.text.replace("\n", "<br>")
    else:
        return " -- --"


@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html')


@app.route("/post_user", methods=['POST'])
def post_user():
    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter(User.email == email).first()
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

    user = User.query.filter(User.email == email).first()
    if user is not None and user.verify_password(password):
        login_user(user)
        flash(message="Successfully Logged in!", category='success')
        return redirect(url_for("index"))
    else:
        flash("Wrong email or password!", 'danger')
        return redirect('login')


def run_extraction_thread(id, image_path):
    with app.app_context():
        schedule = Schedule.query.filter_by(id=id).first()
        while not schedule.isExtracted():
            sleep(1)
        text = extract_text_from_image(image_path)
        text = text if text else ' -- -- '
        obj = ImageText(schedule, text)
        db.session.add(obj)
        db.session.commit()
        return True


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'media' not in request.files:
            return 'No file selected'

        file = request.files['media']

        if file.filename == '':
            return 'No file selected'
        if not allowed_file(file.filename):
            return 'Invalid file type'

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        schedule_to = request.form.get("schedule_to")
        schedule_to = datetime.strptime(schedule_to, "%Y-%m-%dT%H:%M")
        schedule = Schedule(user=current_user, scheduleTo=schedule_to, image=filename)
        db.session.add(schedule)
        db.session.commit()

        # run thread
        extraction_thread = threading.Thread(target=run_extraction_thread, args=(schedule.id, os.path.join(app.config['UPLOAD_FOLDER'], filename)))
        extraction_thread.start()

        return redirect(url_for('index'))
