from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from database import db
from models import LeaveRequest, User
from sqlalchemy import cast, Date, func


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leave_requests.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    leave_requests = LeaveRequest.query.all()
    return render_template('index.html', leave_requests=leave_requests)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('You were successfully logged in!')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Choose a different one.')
            return redirect(url_for('register'))

        db.session.add(new_user)
        db.session.commit()

        flash('Successfully registered! You can now login.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/request_leave', methods=['POST'])
@login_required
def request_leave():
    date_str = request.form['leave_date']
    reason = request.form['reason']

    if not date_str:
        flash('Please enter a date for your leave request.')
        return redirect(url_for('index'))

    try:
        leave_date = datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        flash('Invalid date format. Please use YYYY-MM-DD format.')
        return redirect(url_for('index'))

    existing_request = LeaveRequest.query.filter(func.date(LeaveRequest.leave_date) == leave_date.date()).first()

    if existing_request:
        flash('A leave request already exists for this date.')
        return redirect(url_for('index'))
    elif leave_date.date() <= datetime.today().date():
        flash('You cannot request leave for today or a past date.')
        return redirect(url_for('index'))
    else:
        new_leave_request = LeaveRequest(username=current_user.username, leave_date=leave_date, reason=reason)
        db.session.add(new_leave_request)
        db.session.commit()

        flash('Your leave request has been submitted.')
        return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)