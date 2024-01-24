from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    leave_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(200))

    def __repr__(self):
        return f'<LeaveRequest {self.username} - {self.leave_date}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100))
    # leave_quota = db.Column(db.Integer, default=10)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
