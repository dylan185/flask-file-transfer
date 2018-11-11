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
from wtforms import Form, SelectField, StringField, TextAreaField, PasswordField, BooleanField,validators
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.datastructures import CombinedMultiDict
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Set Upload Location
UPLOAD_FOLDER = '/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'ppt'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# SQL Alchemy DB setup
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/SPFlaskWebServer1'
db = SQLAlchemy(app)

# Initialize
mysql = MySQL(app)

# Set up regexs
username_reg = '^[A-Za-z0-9@_-]*$'
name_reg = '^[\p{P}\s\w]*$'
email_reg = '[^@]+@[^@]+\.[^@]+'
password_reg = '^[A-Za-z0-9@-_?!]*$'
group_reg = '^[A-Za-z0-9 @ -_?!]*$'

####################
# HELPER FUNCTIONS #
####################

# Checks Whitelist and compares file type
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

# Checks if user is admin
def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'is_admin' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized.', 'danger')
            return redirect(url_for('dashboard'))
    return wrap

##########
# MODELS #
##########

class Group(db.Model):
    __tablename__ = 'group'
    group_id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(80), unique=True, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    
    # Relationships
    users = db.relationship('User', back_populates='group')
    files = db.relationship('File', back_populates='group')
    group_status = db.relationship('Status', back_populates='group')

    def __repr__(self):
        return '<Group %r>' % self.groupname

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    register_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    admin_status = db.Column(db.Boolean, nullable=False, default=False)
    
    # Foreign Keys & Relationships
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), nullable=True)
    group = db.relationship('Group', back_populates='users')
    files = db.relationship('File', back_populates='user')
    user_status = db.relationship('Status', back_populates='user')

    def __repr__(self):
        return '<User %r>' % self.username

class File(db.Model):
    __tablename__ = 'file'
    file_id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(80), unique=True, nullable=False)
    file_desc = db.Column(db.Text())
    file_path = db.Column(db.String(100), nullable=False)
    uploader = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    # Foriegn Keys & Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', back_populates='files')
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), nullable=False)
    group = db.relationship('Group', back_populates='files')

    def __repr__(self):
        return '<File %r>' % self.file_name

class Status(db.Model):
    __tablename__ = 'status'
    status_id = db.Column(db.Integer, primary_key=True)
    status_type = db.Column(db.String(20), nullable=False)
    approved = db.Column(db.Boolean, nullable=False, default=False)
    username = db.Column(db.String(100), nullable=True)

    # Foreign Keys & Relationships
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), nullable=True)
    group = db.relationship('Group', back_populates='group_status')
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', back_populates='user_status')
    
    def __repr__(self):
        return '<Status %r>' % self.status_id

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
        validators.DataRequired(),
        validators.EqualTo('confirm', message="Passwords do not match.")
    ])
    confirm = PasswordField('Confirm Password')
    groupnames = SelectField('Group', coerce=int, validators=[
        validators.Optional()
    ])
    admin = BooleanField('Admin')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    form.groupnames.choices = [(g.group_id, g.groupname) for g in Group.query.order_by('groupname')]
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        groupname = form.groupnames.data
        admin = form.admin.data

        # Get group
        group = Group.query.filter_by(groupname=groupname).first()

        # create object
        new_user = User(name=name, email=email, username=username, password=password)
        db.session.add(new_user)

        # Add group request and admin(if any) to status
        new_group_status = Status(status_type='group', user=new_user, group=group, username=username)
        db.session.add(new_group_status)
        
        if admin:
            new_admin_status = Status(status_type='admin', user=new_user, username=username)
            db.session.add(new_admin_status)

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
            # Compare Passwords & get group name
            if sha256_crypt.verify(password_attempt, user.password):
                session['logged_in'] = True
                session['username'] = username
                session['in_group'] = True
                if user.group:
                    session['groupname'] = user.group.groupname
                if user.admin_status:
                    session['is_admin'] = True
                flash('Logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login.'
                return render_template('login.html', error=error)
        else: # No User
            error = 'Username not found.'
            return render_template('login.html', error=error)

    return render_template('login.html')

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
@is_admin
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
    # if session.get('username'):
        # session['is_admin'] = True 
    return render_template('dashboard.html', uploads=File.query.all())

# Upload File Form
class UploadFileForm(FlaskForm):
    file_name = StringField('File Title', [
        validators.Length(min=4, max=35, message="File Title must be between 4 & 35 characters."),
        validators.Regexp(username_reg, message="File Title can contain only letters, numbers or underscores.")
    ])
    file_desc = TextAreaField('Body', [
        validators.Length(max=500),
        validators.Regexp(group_reg, message="The description can only contain letters, numbers, underscores, dashes, exclaimation/question marks, or periods."),
        validators.Optional()
    ])
    upload = FileField('File', validators=[FileRequired()])

# Upload File
@app.route('/upload_file', methods=['GET', 'POST'])
@is_logged_in
@is_in_group
def upload_file():
    form = UploadFileForm()
    # if request.method == 'POST' and form.validate() and allowed_file(form.file.data):
    print(form.validate_on_submit())
    print(form.errors)
    if form.validate_on_submit(): 
        print('========================')
        # file_name = secure_filename(form.file.data)
        file_name = form.file_name.data
        file_desc = form.file_desc.data
        file_path = join(app.config['UPLOAD_FOLDER'], secure_filename(form.upload.data.filename))
        # open(os.path.join(app.config['UPLOAD_FOLDER'], file_name), 'w').write()
        form.upload.data.save(file_path)

        # Get user and group
        user = User.query.filter_by(username=session.get('username')).first()
        group = Group.query.filter_by(groupname=session.get('groupname')).first()

        # Add to DB
        new_file = File(file_name=file_name, file_desc=file_desc, file_path=file_path, uploader=user.username, user=user, group=group)
        db.session.add(new_file)
        db.session.commit()

        flash('File Uploaded!')
        return redirect(url_for('dashboard'))
    return render_template('upload_file.html', form=form)

# View Statuses
@app.route('/view_status', methods=['GET', 'POST'])
@is_logged_in
@is_admin
def view_status():
    return render_template('view_status.html', statuses=Status.query.all())

# Approve Status
@app.route('/approve/<string:id>/')
@is_logged_in
@is_admin
def approval(id):
    status = Status.query.filter_by(status_id=int(id)).first()
    if status.status_type == 'admin':
        status.user.admin_status = True
        db.session.delete(status)
        db.session.commit()
        flash('Admin Status Approved!', 'success')
    if status.status_type == 'group':
        user = status.user
        user.group = status.group
        db.session.delete(status)
        db.session.commit()
        flash('Group Status Approved!', 'success')
    return redirect(url_for('view_status'))

# Decline Status
@app.route('/decline/<string:id>/')
@is_logged_in
@is_admin
def decline(id):
    status = Status.query.filter_by(status_id=int(id)).first()
    db.session.delete(status)
    db.session.commit()
    flash('Declined Status.', 'success')
    return redirect(url_for('view_status'))

if __name__ == '__main__':
    app.secret_key = 'V8EVmF*RfdV!TX055eBI'
    app.run(debug = True)
