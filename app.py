# Some necessary includes: Flask, SQLite and some system functions
from flask import Flask, g, render_template, redirect, request, Response, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sys
#from werkzeug.utils import secure_filename
from subprocess import *
# Tornado web server
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
import tornado.ioloop
import tornado.web

#Debug logger
import logging 
root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

# Just a debugging flag to switch off Flask and Tornado
web = True

def return_dict():
    #Dictionary to store music file information
dict_here = [
	    {'id': 1, 'name': 'Astronaut in the Ocean	', 'link': 'music/masked_wolf_astronaut.mp3', 'genre': 'General', 'rating': 4},
	    {'id': 2, 'name': 'Kohinoor','link': 'music/divine_kohinoor.mp3', 'genre': 'Indian Rap', 'rating': 5},
	    {'id': 3, 'name': 'Mirchi ft.DIVINE', 'link': 'music/divine_mirchi.mp3', 'genre': 'Indian Rap', 'rating': 4},
	    {'id': 4, 'name': 'Lut Gaye', 'link': 'music/lut_gaye_lyrics.mp3', 'genre': 'Bollywood', 'rating': 4},
	    {'id': 5, 'name': 'Chal Bombay', 'link': 'music/divine_chal_bombay.mp3', 'genre': 'Indian Rap', 'rating': 4},
	    {'id': 6, 'name': 'Khairiyat', 'link': 'music/lyrical_khairiyat_chhichhore.mp3', 'genre': 'Bollywood','rating': 5},
	    {'id': 7, 'name': 'Mauli Mauli (Marathi)', 'link': 'music/lai_bhaari_mauli.mp3', 'genre': 'Devotional', 'rating': 5},
	    {'id': 8, 'name': 'Vaathi Coming', 'link': 'music/master_vaathi_coming.mp3', 'genre': 'Tollywood', 'rating': 3},
	    {'id': 9, 'name': 'O Saathi', 'link': 'music/O_Saathi_Baaghi_2.mp3', 'genre': 'Bollywood', 'rating': 4},
	    {'id': 10, 'name': 'Taarefan', 'link': 'music/Taarefan.mp3', 'genre': 'Bollywood', 'rating': 3},
	    {'id': 11, 'name': 'Zingaat', 'link': 'music/Zingaat.mp3', 'genre': 'Marathi', 'rating': 5},
	    {'id': 12, 'name': 'Brown Rang', 'link': 'music/Brown_Rang _Yo_Yo_HoneySingh.mp3', 'genre': 'Rap', 'rating': 4.5},
	    {'id': 13, 'name': 'Demo Video', 'link': 'music/demovideo.mp4', 'genre': 'Cartoon:Video', 'rating': 4.5},
	    {'id': 14, 'name': 'Machayenge-Emiway', 'link': 'music/machayenge_v.mp4', 'genre': 'Video Song', 'rating': 5},
	    {'id': 15, 'name': 'Brown Munde', 'link': 'music/brown_munde.mp4', 'genre': 'Video Song', 'rating': 5}
	]
return dict_here

# To execute commands outside of Python
def run_cmd(cmd):
   p = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
   output = p.communicate()[0]
   return output

# Initialize Flask.

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')

def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid Username or Password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login2.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
		#return'<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
 
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    general_Data = {
        'title': 'Media Server'}
    stream_entries = return_dict()
    return render_template('main_bootstrap.html',entries = stream_entries, **general_Data)
  	
    # We do stop the music...
@app.route('/stop')
def stop_music():
    run_cmd('mpc stop')
    return redirect('/dashboard')

    # Play a stream from the id provided in the html string. 
    # We use mpc as actual program to handle the mp3 streams.
@app.route('/<int:stream_id>')
def streammp3(stream_id):
    def generate():
        data = return_dict()
        count = 1
        for item in data:
            if item['id'] == stream_id:
            
                song = item['link']
        with open(song, "rb") as fwav:
            data = fwav.read(10024)
            while data:
                yield data
                data = fwav.read(10024)
                logging.debug('Music data fragment : ' + str(count))
                count += 1
                
    return Response(generate(), mimetype="video/mp4")

   # To gracefully shutdown the web application. 
@app.route('/shutdown_server', methods=['POST', 'GET'])
def shutdown():
   IOLoop.instance().stop()
   return 'Shutting down the server.\nSee you soon :)'




# Here comes the main call.
#  To launch a Tornado server with HTTPServer.
if __name__ == "__main__":
	port = 8080
        http_server = HTTPServer(WSGIContainer(app))
        logging.debug("\nStarted Server, Kindly visit http://localhost:" + str(port))
        http_server.listen(port)
	tornado.ioloop.IOLoop.current().start()
