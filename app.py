from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix  # Dodajemy import

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)  # Dodajemy middleware ProxyFix

app.secret_key = "secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///service_hours.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class ServiceHours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    hours = db.Column(db.Integer, nullable=False)

@app.route('/')
def index():
    if 'username' in session:
        service_hours = ServiceHours.query.filter_by(user_id=session['user_id']).all()
        return render_template('index.html', username=session['username'], service_hours=service_hours)
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Sprawdzanie, czy użytkownik o danej nazwie już istnieje
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = 'Username already exists. Please choose a different one.'
            return render_template('register.html', error=error)
        
        # Haszowanie hasła i zapisanie nowego użytkownika do bazy danych
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error=True)
    return render_template('login.html', error=False)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/add_hours', methods=['POST'])
def add_hours():
    if 'username' in session:
        user_id = session['user_id']
        hours = request.form['hours']
        service_hours = ServiceHours(user_id=user_id, hours=hours)
        db.session.add(service_hours)
        db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
