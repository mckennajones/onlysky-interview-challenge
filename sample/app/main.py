# coding: utf-8

from datetime import datetime
import os
from calendar import month_name
from flask import flash, Flask, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, LoginManager, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import extract, exists
from flask_wtf import FlaskForm
from werkzeug.debug import DebuggedApplication
from wtforms import PasswordField, StringField, HiddenField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange
from wtforms.widgets import HiddenInput
from wtforms.ext.sqlalchemy.fields import QuerySelectField

from app import commands

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://{}:{}@{}:3306/{}'.format(
    os.getenv('MYSQL_USERNAME', 'web_user'),
    os.getenv('MYSQL_PASSWORD', 'password'),
    os.getenv('MYSQL_HOST', 'db'), os.getenv('MYSQL_DATABASE', 'sample_app'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'this is something special'

if app.debug:
    app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

db = SQLAlchemy(app)
commands.init_app(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id) if user_id else None

# Classes
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))

    def __repr__(self):
        return '<User %r>' % self.email

    def check_password(self, password):
        return self.password == password


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    body = db.Column(db.Text)
    pub_date = db.Column(db.DateTime)

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship(
        'Category', backref=db.backref('posts', lazy='dynamic'))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship(
        'User', backref=db.backref('posts', lazy='dynamic')
    )

    def __init__(self, title, body, category, user, pub_date=None):
        self.title = title
        self.body = body
        if pub_date is None:
            pub_date = datetime.utcnow()
        self.pub_date = pub_date
        self.category = category
        self.user = user

    def __repr__(self):
        return '<Post %r>' % self.title


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Category %r>' % self.name

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(email=self.email.data).one_or_none()
        if user:
            password_match = user.check_password(self.password.data)
            if password_match:
                self.user = user
                return True

        self.password.errors.append('Invalid email and/or password specified.')
        return False

def GetCategories():
    return Category.query.order_by('name')

class NewPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = HiddenField('Body', validators=[DataRequired()])
    length = IntegerField(
                label='',
                validators=[
                    NumberRange(min=10)
                ],
                widget=HiddenInput()
     )
    category = QuerySelectField(
                    'Category', 
                    query_factory=GetCategories, 
                    get_label='name',
                    allow_blank=True, 
                    blank_text='--Create New--')
    newCategory = StringField('New Category')

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        # self.user = None

    def validate(self):
        valid = FlaskForm.validate(self)
        
        # An empty Quill editor has length 1
        if self.length.data < 11:
            flash('Blog posts must be at least 10 characters.', 'danger')
            return False

        if not valid:
            return False

        return True

# Routes
@app.route('/<int:year>/<int:month>/')
@app.route('/')
def index(year=None, month=None):
    args = request.args

    page = int(args.get('page')) if args.get('page') is not None else None
    
    if year is not None and month is not None:
        flash(f'Showing posts from {month_name[month]}, {year}', 'info')
        posts = Post.query.filter(extract('year', Post.pub_date) == year, extract('month', Post.pub_date) == month)
    else:
        posts = Post.query.filter(Post.pub_date < datetime.now())

    posts = posts.order_by(Post.pub_date.desc()).paginate(page=page, per_page=10)

    archiveDates = db.session.query(extract('year', Post.pub_date).label('year'),
                                    extract('month', Post.pub_date).label('month'))\
                              .order_by(Post.pub_date.desc())\
                              .group_by(extract('year', Post.pub_date), 
                                        extract('month', Post.pub_date))\
                              .all()

    return render_template('index.html', posts=posts, dates=archiveDates, months=month_name)


@app.route('/auth/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        login_user(form.user)
        flash('Logged in successfully.', 'success')
        return redirect(request.args.get('next') or url_for('index'))

    return render_template('login.html', form=form)


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/account/')
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/new-post/', methods=['GET', 'POST'])
def newPost():
    form = NewPostForm()
    
    if not current_user.is_authenticated:
        flash('Please login first.', 'warning')
        return redirect('/auth/login/')
    
    if form.validate_on_submit():
        category = form.category.data

        if category is None:
            category = Category(name=form.newCategory.data)
            db.session.add(category)
            db.session.commit()

        post = Post(title=form.title.data, body=form.body.data, category=category, user=current_user)

        db.session.add(post)
        db.session.commit()

        flash('New Post created successfully.', 'success')
        return redirect(request.args.get('next') or url_for('index'))

    return render_template('newPost.html', form=form, user=current_user)

@app.before_first_request
def initialize_data():
    # just make sure we have some sample data, so we can get started.
    user = User.query.filter_by(email='blogger@sample.com').one_or_none()
    if user is None:
        user = User(email='blogger@sample.com', password='password')
        db.session.add(user)
        db.session.commit()


if __name__ == "__main__":
    app.run()
