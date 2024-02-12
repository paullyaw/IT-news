from imports import UserMixin, datetime, Flask, Limiter, get_remote_address, SQLAlchemy, LoginManager

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'mysecretkey'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):  # информация для базы данных пользователей
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class News(db.Model):  # информация для базы данных новостей
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(100), nullable=True)
    content = db.Column(db.Text, nullable=False)
    photo = db.Column(db.String, nullable=False, default="cat.jpeg")
    category = db.Column(db.String(20), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.today().date())
    views = db.Column(db.Integer, default=0)
    link = db.Column(db.String(100), nullable=True)


class Games(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    photo = db.Column(db.String, nullable=False, default="cat.jpeg")
    link = db.Column(db.String(100), nullable=False)
