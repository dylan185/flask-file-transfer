#####################################
#           Dylan Forsyth           #
#   Flask File Transfer WebServer   #
#         November 10, 2018         #
#####################################

import os
import datetime
import collections
from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, SelectField, StringField, TextAreaField, PasswordField, validators, FileField
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Config DB
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'SPFlaskWebServerUser'
# app.config['MYSQL_PASSWORD'] = '123456'
# app.config['MYSQL_DB'] = 'SPFlaskWebServer'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Set Upload Location
UPLOAD_FOLDER = '/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'ppt'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# SQL Alchemy setup
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:dylan185@localhost/SPFlaskWebServer1'
db = SQLAlchemy(app)

# Initialize
mysql = MySQL(app)

# Set up regexs
username_reg = '^[A-Za-z0-9@_-]*$'
name_reg = '^[\p{P}\s\w]*$'
email_reg = '[^@]+@[^@]+\.[^@]+'
password_reg = '^[A-Za-z0-9@-_?!]*$'
group_reg = '^[A-Za-z0-9 ]*$'

##########
# MODELS #
##########

class Group(db.Model):
    group_id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(80), unique=True, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __repr__(self):
        return '<Group %r>' % self.groupname

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    register_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    
    # Foreign Keys
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), nullable=True)
    group = db.relationship('Group', backref=db.backref('user_groups', lazy=True))

    def __repr__(self):
        return '<User %r>' % self.username

class File(db.Model):
    file_id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(80), unique=True, nullable=False)
    file_desc = db.Column(db.Text())
    file_path = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    # Foriegn Keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('file_users', lazy=True))
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), nullable=False)
    group = db.relationship('Group', backref=db.backref('file_groups', lazy=True))

    def __repr__(self):
        return '<File %r>' % self.file_name

##############
# HTML PAGES #
##############

# Index
@app.route('/')
def index():
    return render_template('index.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

# User Registration Form
class RegisterForm(Form):
    name = StringField('Name', [
        validators.Length(min=1, max=80, message="Name must be between 1 & 80 characters."), 
        validators.Regexp(name_reg, message="Name must contain only letters & spaces.")
        ])
    username = StringField('Username', [
        validators.Length(min=4, max=25, message="Username must be between 4 & 25 characters."),
        validators.Regexp(username_reg, message="Username must contain only letters, numbers or underscores.")
        ])
    email = StringField('Email', [
        validators.Length(min=6, max=30, message="Email must be between 6 & 30 characters."),
        validators.Regexp(email_reg, message="Email must follow the format '####'@'######'.com & only contain letters, numbers, underscores, dashes, or periods.")
        ])
    password = PasswordField('Password', [
        validators.Length(min=5, max=30, message="Password must be between 5 & 30 characters."),
        validators.Regexp(password_reg, message="Passwords may only contain letters, numbers, underscores, dashes, exclaimation/question marks, or periods."),
        validators.DataRequired(),validators.EqualTo('confirm', message="Passwords do not match.")
        ])
    confirm = PasswordField('Confirm Password')
    groupnames = SelectField('Group', choices=[(g.group_id, g.groupname) for g in Group.query.order_by('groupname')] )

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        groupname = form.groupnames.data

        # Get group
        group = Group.query.filter_by(groupname=groupname).first()

        # create object
        new_user = User(name=name, email=email, username=username, password=password, group=group)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user info for login
        username = request.form['username']
        password_attempt = request.form['password']

        # Get account and verify
        user = User.query.filter_by(username=username).first()
        if user:
            # Compare Passwords
            if sha256_crypt.verify(password_attempt, user.password):
                session['logged_in'] = True
                session['username'] = username
                session['in_group'] = True
                session['groupname'] = user.groupname
                flash('Logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login.'
                return render_template('login.html', error=error)
        else: # No User
            error = 'Username not found.'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login.', 'danger')
            return redirect(url_for('login'))
    return wrap

# Check if user is in group
def is_in_group(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'in_group' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please join group.', 'danger')
            return redirect(url_for('dashboard'))
    return wrap

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are logged out.', 'success')
    return redirect(url_for('login'))

# Group Creation Form
class GroupForm(Form):
    groupname = StringField('Group Name', [
        validators.Length(min=4, max=35, message="Group Name must be between 4 & 35 characters."),
        validators.Regexp(regex=group_reg, message="Group Name must contain only letters, numbers and spaces.")
        ])

# Create Group
@app.route('/create_group', methods=['GET', 'POST'])
@is_logged_in
def create_group():
    form = GroupForm(request.form)
    if request.method == 'POST' and form.validate():
        groupname = form.groupname.data

        # Add to DB
        new_group = Group(groupname=groupname)
        db.session.add(new_group)
        db.session.commit()

        flash('Group Created.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_group.html', form=form)

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')

# Upload File Form
class UploadFileForm(Form):
    file_name = StringField('File Name', [
        validators.Length(min=4, max=35, message="Group Name must be between 4 & 35 characters."),
    ])
    file_desc = TextAreaField('Body', [
        validators.Length(min=30)
    ])
    file = FileField()

# Upload File
@app.route('/upload_file', methods=['GET', 'POST'])
@is_logged_in
@is_in_group
def upload_file():
    form = UploadFileForm(request.form)
    if request.method == 'POST' and form.validate():
        file_name = secure_filename(form.file.data.filename)
        file_desc = form.desc.data
        form.file.data.save('uploads/' + file_name)

        # Get user and group
        user = User.query.filter_by(username=session.get('username')).first()
        group = Group.query.filter_by(groupname=session.get('groupname')).first()

        # Add to DB
        new_file = File(file_name=file_name, file_desc=file_desc, file_path='uploads/%s'%file_name, user=user, group=group)

if __name__ == '__main__':
    app.secret_key = 'V8EVmF*RfdV!TX055eBI'
    app.run(debug = True)
