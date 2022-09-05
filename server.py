import os
import base64
import onetimepass
import pyqrcode
import io
from flask import Flask
from werkzeug.security import *
from flask_sqlalchemy import *
from flask_login import *
from flask_bootstrap import *
from flask_wtf import *
from wtforms import *
from wtforms.validators import *

#создание Flask
app = Flask(__name__)
#настройки бд для пользователей
app.config.from_object('bd')
sql = SQLAlchemy(app)
#настроки для пользователей
login_manager = LoginManager(app)
#бутстрап
bootstrap = Bootstrap(app)

#класс пользователя
class User(UserMixin, sql.Model):
    #таблица бд
    __tablename__ = 'users'
    #поля таблицы
    id = sql.Column(sql.Integer, primary_key=True)
    name_user = sql.Column(sql.String(64), index=True)
    password_hash = sql.Column(sql.String(128))
    otp_key_secret = sql.Column(sql.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_key_secret is None:
            #создание ключа
            self.otp_key_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    #функции хеширования, проверки и правльности ввода пароля
    @property
    def password(self):
        raise AttributeError('Ошибка пароля',encoding="utf-8")
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    def password_check(self, password):
        return check_password_hash(self.password_hash, password)

    #создание ключа
    def totp_get(self):
        return 'otpauth://totp/2FA:{0}?secret={1}&issuer=2FA'.format(self.name_user, self.otp_key_secret)


    #проверка токена по ключу
    def totp_check(self, token):
        return onetimepass.valid_totp(token, self.otp_key_secret)

    ######тест 
    def totp_check1(self, token):
        return self.otp_key_secret

#загрузка пользователя из базы по имени
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#класс регистрации пользователя
class Form_Reg(FlaskForm):
    name_user = StringField('Логин', validators=[DataRequired(), Length(1, 64)],encoding="utf-8")
    password = PasswordField('Пароль', validators=[DataRequired()],encoding="utf-8")
    password_again = PasswordField('Повторите пароль',validators=[DataRequired(), EqualTo('password')],encoding="utf-8")
    submit = SubmitField('Зарегистрироваться',encoding="utf-8")

#класс входа пользователя
class Form_Log(FlaskForm):
    name_user = StringField('Логин', validators=[DataRequired(), Length(1, 64)],encoding="utf-8")
    password = PasswordField('Пароль', validators=[DataRequired()],encoding="utf-8")
    token = StringField('Токен', validators=[DataRequired(), Length(6, 6)],encoding="utf-8")
    submit = SubmitField('Войти',encoding="utf-8")

#главное окно
@app.route('/')
def index():
    return render_template('index.html')

#окно регистрации
@app.route('/reg', methods=['GET', 'POST'])
def reg():
    #проверка логирования пользователя
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = Form_Reg()
    if form.validate_on_submit():
        user = User.query.filter_by(name_user=form.name_user.data).first()
        if user is not None:
            flash('Это имя пользователя уже занято',encoding="utf-8")
            return redirect(url_for('reg'))
        #добавление пользователя в базу данных
        user = User(name_user=form.name_user.data, password=form.password.data)
        sql.session.add(user)
        sql.session.commit()

        #открыть старницу двуэтапной
        session['name_user'] = user.name_user
        return redirect(url_for('_2fa'))
    return render_template('reg.html', form=form)

#двухэтапная аутификация
@app.route('/_2fa')
def _2fa():
    #если нет ссессии то выйти
    if 'name_user' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(name_user=session['name_user']).first()
    #проверка включеного кеша
    if user is None:
        return redirect(url_for('index'))
    #создание страницы с qr кодом
    return render_template('qr_qr.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

#формирование QR кода
@app.route('/QR')
def QR():
    #проверка,есть ли сессия для пользователя
    if 'name_user' not in session:
        abort(404)
    #запрос данных из бд по логину
    user = User.query.filter_by(name_user=session['name_user']).first()
    if user is None:
        abort(404)        
    del session['name_user']

    #создание кода
    url = pyqrcode.create(user.totp_get())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

#вход в учётную запись
@app.route('/login', methods=['GET', 'POST'])
def login():
    #проверка логирования пользователя
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    #создание формы для входа
    form = Form_Log()
    #проверка на существание пользоватиеля
    if form.validate_on_submit():
        user = User.query.filter_by(name_user=form.name_user.data).first()
        if user is None or not user.password_check(form.password.data) or not user.totp_check(form.token.data):
            #flash(user.totp_check1(form.token.data))
            #ошибка входа
            flash('Ошибка входа, проверьте введенные данные',encoding="utf-8")
            return redirect(url_for('login'))
        #вход пользователя
        login_user(user)
        flash('Авторизация пройдена',encoding="utf-8")
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

#выход из учётной записи
@app.route('/quit')
def quit():
    #выход пользователя
    logout_user()
    return redirect(url_for('index'))

#если нет файла базы данных создать его
sql.create_all()

#главная программа
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

