from datetime import datetime
from flask import Flask, render_template, request, redirect, session, flash, send_file, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import os

app = Flask(__name__)
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
    subtitle = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    photo = db.Column(db.String, nullable=False)
    category = db.Column(db.String(20), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.today())


class AccountForm(FlaskForm):  # форма для настроек аккаунта
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Save Changes')



with app.app_context():  # создание базы банных
    db.create_all()


@login_manager.user_loader
def load_user(user_id):  # создание сессии при авторизации пользователя
    return User.query.get(int(user_id))


@app.route('/')
def index():
    news_list = News.query.filter_by().all()  # главная страница
    return render_template('base.html', all_news=news_list)


@app.route('/home')
def home():  # домашняя страница пользователя
    news_list = News.query.filter_by().all()
    return render_template('base.html', all_news=news_list)


@app.route('/register', methods=['GET', 'POST'])
def register():  # регистрация пользователя
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password, role="reader")
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():  # авторизация пользователя
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            login_user(user)
            return redirect("/home")
        else:
            return render_template('login.html', message='Invalid email or password')
    return render_template('login.html')


@app.route('/logout')
def logout():  # выход из аккаунта и конец сессии
    logout_user()
    session.pop('user_id', None)
    return redirect("/")


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():  # настройки аккаунта
    form = AccountForm()
    if request.method == 'POST':  # изменение данных пользователя
        user = User.query.filter_by(id=current_user.id).first()
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect('/account')
    elif request.method == 'GET':  # получение данных о пользователе
        user = User.query.filter_by(id=current_user.id).first()
        form.username.data = user.username
        form.email.data = user.email
    user = User.query.filter_by(id=current_user.id).first()
    if user.role == "reader":
        return render_template('account.html', form=form)
    elif user.role == "admin":
        return render_template('admin.html', form=form)


# Главная страница панели администрирования
@login_required
@app.route("/dashboard")
def dashboard():
    news = News.query.all()
    return render_template("dashboard.html", news=news)


# Страница редактирования новостей
@login_required
@app.route("/edit_news/<int:id>", methods=["GET", "POST"])
def edit_news(id):
    news = News.query.get_or_404(id)
    if request.method == "POST":
        news.title = request.form['title']
        news.subtitle = request.form['subtitle']
        news.content = request.form['content']
        news.category = request.form['category']
        db.session.commit()
        return redirect("/")
    else:
        return render_template("edit_news.html", news=news)


# Страница удаления новостей
@login_required
@app.route("/delete_news/<int:id>")
def delete_news(id):
    news = News.query.get_or_404(id)
    db.session.delete(news)
    db.session.commit()
    return redirect("/")


@app.route('/neural')
def neural():
    news_list = News.query.filter_by(category="neural").all()
    return render_template('neural.html', all_news=news_list)


@app.route('/technique')
def technique():
    news_list = News.query.filter_by(category="technique").all()
    return render_template('technique.html', all_news=news_list)


@app.route('/games')
def games():
    news_list = News.query.filter_by(category="games").all()
    return render_template('games.html', all_news=news_list)


@app.route('/add_news', methods=['GET', 'POST'])
@login_required
def add_news():
    if request.method == 'POST':
        title = request.form['title']
        subtitle = request.form['subtitle']
        content = request.form['content']
        photo = request.files["photo"]
        category = request.form['category']
        filename = photo.filename
        photo.save(os.path.join('static', 'img', filename))
        photo_data = photo.read()
        news = News(title=title, subtitle=subtitle, content=content, photo=filename, category=category)
        db.session.add(news)
        db.session.commit()
        return redirect('/home')
    return render_template('add_news.html')

@app.route('/del_news')
def del_news():
    news_list = News.query.filter_by().all()
    return render_template('del.html', all_news=news_list)


@app.route("/editor")
def editor():
    news_list = News.query.filter_by().all()
    return render_template('edit.html', all_news=news_list)


@app.route('/read_news/<int:id>')
def read_news(id):
    news = News.query.get_or_404(id)
    return render_template("read_news.html", news=news)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
