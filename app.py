from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config DB
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'SPFlaskWebServerUser'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'SPFlaskWebServer'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize
mysql = MySQL(app)


#######################
#      HTML PAGES     #
#######################

# Index
@app.route('/')
def index():
    return render_template('index.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

# Uploads or Images
@app.route('/uploads')
def uploads():
    return render_template('uploads.html')

# Single Image
@app.route('/uploads/<string:id>/')
def get_image(id):
    return render_template('image.html', id=id)

# Upload
@app.route('/upload')
def upload_file():
   return render_template('upload.html')

# User Registration Form
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=30)])
    password = PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match.'),
    ])
    confirm = PasswordField('Confirm Password')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        # commit DB then close connection
        mysql.connection.commit()
        cur.close()
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

        # Create cursor
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Fetch password hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_attempt, password):
                session['logged_in'] = True
                session['username'] = username
                flash('Logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login.'
                return render_template('login.html', error=error)
            # close connection
            cur.close()

        else: # No user 
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

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are logged out.', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.secret_key = 'V8EVmF*RfdV!TX055eBI'
    app.run(debug = True)
