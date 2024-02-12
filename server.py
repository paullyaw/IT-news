from imports import *
from data import *


class AccountForm(FlaskForm):  # форма для настроек аккаунта
    username = StringField('Username', validators=[DataRequired(),
                                                   Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Save Changes')


with app.app_context():  # создание базы банных
    db.create_all()


def usernames():  # получаем текущее имя пользователя
    username = session.get('username')
    return username


@login_manager.user_loader
def load_user(user_id):  # создание сессии при авторизации пользователя
    return User.query.get(int(user_id))


@app.route("/")
@limiter.limit("5/second", override_defaults=False)
def animation():  # анимация в начале
    return render_template("animation.html")


@app.route('/main')
@limiter.limit("5/second", override_defaults=False)
def index():  # главная страница
    news_list = News.query.filter_by().all()
    news_list = news_list[::-1]
    games = Games.query.filter_by().all()
    return render_template('base.html', all_news=news_list, games=games)


@app.route('/news')
@limiter.limit("5/second", override_defaults=False)
def main_news():
    news_list = News.query.filter_by().all()
    news_list = news_list[::-1]
    return render_template("neural.html", all_news=news_list)


@app.route('/home')
@limiter.limit("3/second", override_defaults=False)
def home():  # домашняя страница пользователя
    news_list = News.query.filter_by().all()
    news_list = news_list[::-1]
    username = usernames()
    return render_template('base.html', all_news=news_list, username=username)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/second", override_defaults=False)
def register():  # регистрация пользователя
    if request.method == 'POST':
        username = request.form['username']
        username = username.lower()
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password, role="writer")
        db.session.add(new_user)
        db.session.commit()
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/second", override_defaults=False)
def login():  # авторизация пользователя
    if request.method == 'POST':
        username = request.form['username']
        username = username.lower()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=90)
            login_user(user)
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie('username', username)
            return resp
        else:
            return render_template('login.html', message='Invalid email or password')
    return render_template('login.html')


@app.route('/logout')
@limiter.limit("3/second", override_defaults=False)
def logout():  # выход из аккаунта и конец сессии
    session.clear()
    logout_user()
    resp = make_response(redirect("/"))
    resp.set_cookie('username', '', expires=0)
    return resp


@app.route('/account', methods=['GET', 'POST'])
@limiter.limit("5/second", override_defaults=False)
@login_required
def account():  # настройки аккаунта
    form = AccountForm()
    username = usernames()
    if request.method == 'POST':  # изменение данных пользователя
        user = User.query.filter_by(id=current_user.id).first()
        if check_password_hash(user.password, form.password.data):
            user.username = form.username.data
            user.email = form.email.data
            db.session.commit()
            flash('Your account has been updated!', 'success')
            return redirect('/account')
        else:
            flash('You entered wrong password', 'error')
            return redirect('/account')
    elif request.method == 'GET':  # получение данных о пользователе
        username = request.cookies.get('username')
        user = User.query.filter_by(id=current_user.id).first()
        form.username.data = user.username
        form.email.data = user.email
        form.password.data = user.password
    return render_template('account.html', form=form, username=username, user=user)


@login_required
@app.route("/writers")
@limiter.limit("10/second", override_defaults=False)
def writers():
    users = User.query.all()
    print(users)
    return render_template("writers.html", users=users)


# Главная страница панели администрирования
@login_required
@app.route("/dashboard")
@limiter.limit("10/second", override_defaults=False)
def dashboard():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        username = usernames()
        if user.role == "admin":
            news = News.query.all()
            users = User.query.all()
            return render_template("dashboard.html", news=news, username=username)
        elif user.role == "writer":
            news = News.query.all()
            return render_template("dbw.html", news=news, username=username)
        else:
            return render_template("login.html")
    except AttributeError:
        return render_template("login.html")


# Страница редактирования новостей
@login_required
@app.route("/edit_news/<int:id>", methods=["GET", "POST"])
@limiter.limit("10/second", override_defaults=False)
def edit_news(id):
    try:
        user = User.query.filter_by(id=current_user.id).first()
        username = usernames()
        if user.role == "admin":
            news = News.query.get_or_404(id)
            username = usernames()
            if request.method == "POST":
                news.title = request.form['title']
                news.subtitle = request.form['subtitle']
                news.content = request.form['content']
                news.category = request.form['category']
                db.session.commit()
                return redirect("/editor")
            else:
                return render_template("edit_news.html", news=news, username=username)
        else:
            abort(404)
    except AttributeError:
        abort(404)


# Страница удаления новостей
@login_required
@app.route("/delete_news/<int:id>")
@limiter.limit("3/second", override_defaults=False)
def delete_news(id):
    try:
        user = User.query.filter_by(id=current_user.id).first()
        username = usernames()
        if user.role == "admin":
            news = News.query.get_or_404(id)
            db.session.delete(news)
            db.session.commit()
            return redirect("/del_news")
        else:
            abort(404)
    except AttributeError:
        abort(404)
    news = News.query.get_or_404(id)
    db.session.delete(news)
    db.session.commit()
    return redirect("/del_news")


@app.route('/it')  # страница с новостями про нейросети
@limiter.limit("3/second", override_defaults=False)
def it():
    news_list = News.query.filter_by(category="neural").all()
    username = usernames()
    news_list = news_list[::-1]
    return render_template('it.html', all_news=news_list, username=username)


@app.route('/game')
@limiter.limit("3/second", override_defaults=False)
# страница с новостями про технику
def game():
    games = Games.query.filter_by().all()
    username = usernames()
    games = games[::-1]
    return render_template('game.html', all_news=games, username=username)


@app.route('/memory_game')
def memory_game():
    return render_template("index.html")


@app.route('/technique')
@limiter.limit("3/second", override_defaults=False)
def technique():
    news_list = News.query.filter_by(category="technique").all()
    username = usernames()
    news_list = news_list[::-1]
    return render_template('technique.html', all_news=news_list, username=username)


@app.route("/flappy_bird")
def flappy_bird():
    return render_template("bird.html")


@app.route('/games')
@limiter.limit("3/second", override_defaults=False)
# страница с новостями про игры
def games():
    news_list = News.query.filter_by(category="games").all()
    username = usernames()
    news_list = news_list[::-1]
    games = Games.query.filter_by().all()
    return render_template('games.html', all_news=news_list, username=username, games=games)


@app.route('/add_news', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@login_required
# страница с формой добавления новостей
def add_news():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        username = usernames()
        if user.role == "admin":
            username = usernames()
            if request.method == 'POST':
                title = request.form['title']
                subtitle = request.form['subtitle']
                content = request.form['content']
                photo = request.files["photo"]
                category = request.form['category']
                filename = photo.filename
                try:
                    photo.save(os.path.join('static', 'img', filename))
                    photo_data = photo.read()
                    news = News(title=title, subtitle=subtitle, content=content, photo=filename, category=category)
                except IsADirectoryError:
                    news = News(title=title, subtitle=subtitle, content=content, category=category)
                db.session.add(news)
                db.session.commit()
                return redirect('/dashboard')
            return render_template('add_news.html', username=username)
        else:
            abort(404)
    except AttributeError:
        abort(404)
    news = News.query.get_or_404(id)
    db.session.delete(news)
    db.session.commit()
    return redirect("/del_news")


@app.route('/del_news')
# панель удаления новостей
@limiter.limit("10/second", override_defaults=False)
def del_news():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        username = usernames()
        if user.role == "admin":
            news_list = News.query.filter_by().all()
            news_list = news_list[::-1]
            username = usernames()
            return render_template('del.html', all_news=news_list, username=username)
        else:
            abort(404)
    except AttributeError:
        abort(404)


@app.route("/editor")
# панель редактирования новостей
@limiter.limit("10/second", override_defaults=False)
def editor():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        username = usernames()
        if user.role == "admin":
            news_list = News.query.filter_by().all()
            username = usernames()
            news_list = news_list[::-1]
            return render_template('edit.html', all_news=news_list, username=username)
        else:
            abort(404)
    except AttributeError:
        abort(404)


@app.route('/read_news/<int:id>')
# чтение новостей
@limiter.limit("3/second", override_defaults=False)
def read_news(id):
    username = usernames()
    news_list = News.query.filter_by().all()
    for idx, i in enumerate(news_list):
        if i.id == id:
            next_idx = idx + 1
            back = idx - 1
            try:
                next = news_list[next_idx].id
            except IndexError:
                next = i.id
            try:
                back = news_list[back].id
            except IndexError:
                back = i.id
    lenght = len(news_list)
    news = News.query.get_or_404(id)
    locale.setlocale(locale.LC_ALL, 'ru_RU.utf-8')
    date = news.date.strftime("%d %B %Y")
    neural_id = []
    games_id = []
    technique_id = []
    for i in News.query.filter_by(category="neural").all():
        neural_id.append(i.id)
    for i in News.query.filter_by(category="games").all():
        games_id.append(i.id)
    for i in News.query.filter_by(category="technique").all():
        technique_id.append(i.id)
    return render_template("read_news.html", news=news, username=username, lenght=lenght,
                           all_news=news_list, next=next,
                           back=back, date=date, neural=neural_id,
                           games=games_id, technique=technique_id)


@app.route("/delete_user/<int:user_id>", methods=['POST'])
@login_required
def delete_user(user_id):
    try:
        if current_user.role == "admin":
            user_to_delete = User.query.get(user_id)
            db.session.delete(user_to_delete)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return render_template("base.html")
    except AttributeError:
        return render_template("base.html")


@app.route("/daily_news")
def daily_news():
    today = str(datetime.today().strftime('%Y-%m-%d 00:00:00')) + ".000000"
    print(today)
    all_news = News.query.filter_by(date=today).all()
    all_news = all_news[::-1]
    return render_template("daily.html", all_news=all_news)


def main():  # запуск сервера
    port = 5000
    app.run(debug=True, port=port)


if __name__ == '__main__':
    main()
