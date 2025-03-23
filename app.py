import datetime
from flask import Flask, jsonify, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
from flask import request
from flask_mail import Mail, Message

load_dotenv()

app = Flask(__name__, template_folder='templates')
bcrypt = Bcrypt(app)
mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') #connects to the database
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'myfirstappofstance76545secretkey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app) #create database instance 
app.app_context().push()
#creating tables
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    role = db.Column(db.String(20), nullable=False)
    affiliation = db.Column(db.String(20), nullable=True)
    expertise = db.Column(db.String(20), nullable=True)
    manuscripts = db.relationship('Manuscript', backref='author', lazy=True)
    reviews = db.relationship('Review', backref='reviewer', lazy=True)

class Manuscript(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    abstract = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('submitted', 'pending_review', 'in_review', 'accepted', 'rejected', name='manuscript_status'), default='submitted')
    submission_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    keywords = db.Column(db.String(200), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviews = db.relationship('Review', backref='manuscript', lazy=True)
    file_path = db.Column(db.String(255))

    def __repr__(self):
        return f"Manuscript('{self.title}', '{self.status}')"

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    manuscript_id = db.Column(db.Integer, db.ForeignKey('manuscript.id'), nullable=False)
    feedback = db.Column(db.Text)
    score = db.Column(db.Integer) # Add a score to quantify the review quality
    status = db.Column(db.Enum('pending', 'accepted', 'rejected', 'submitted', name='review_status'), default='pending')
    assigned_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    submission_date = db.Column(db.DateTime) # Only set when the reviewer submits the review.

    def __repr__(self):
        return f'<Review for Manuscript {self.manuscript_id} by Reviewer {self.reviewer_id}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False) # Flag to indicate if the notification has been read.
    type = db.Column(db.String(20), nullable=False) # Type of notification (e.g., 'review_assigned', 'review_submitted', etc.)
    user = db.relationship('User', backref='notifications') # Add a relationship for easier access to the user.
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Notification for User {self.user_id}>'


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    firstname = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "First Name"})
    lastname = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Last Name"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20), EqualTo('confirm_password', 'passwords must match')], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password')
    role = SelectField('Role', choices=[('', 'Select Role'), ('author', 'Author'), ('reviewer', 'Reviewer'), ('editor', 'Editor')])
    submit = SubmitField('Create Account')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

def send_review_request_email(user_email, manuscript_title):
    try:
        msg = Message(
            'New Review Request',
            sender=app.config['MAIL_USERNAME'],
            recipients=[user_email]
        )
        msg.body = f'''You have been requested to review the manuscript: "{manuscript_title}"
        
Please log in to your account to view the full manuscript and submit your review.

Best regards,
The Review System Team
'''
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form = form)

@app.route('/dashboard', methods=['GET', 'POST'])
#@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'] )
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        print("Form data:", form.username.data, form.password.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            username=form.username.data, 
            password=hashed_password,
            email=form.username.data,
            role=form.role.data
        )

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template('register.html', form=form)

@app.route('/review', methods=['GET', 'POST'])
@login_required
def review():
    #manuscripts = Manuscript.query.all()
    #return render_template('review.html', manuscripts=manuscripts)
    return render_template('review.html')

@app.route('/submit_manuscript', methods=['GET', 'POST'])
@login_required
def submit_manuscript():
    return render_template('submit_manuscript.html')

@app.route('/manuscripts', methods=['POST'])
@login_required
def create_manuscript():
    try:
        title = request.forms.get('title')
        abstract = request.forms.get('abstract')
        content = request.forms.get('content')
        keywords = request.forms.get('keywords')
        author_id = request.forms.get('author_id')

        # Validate required fields
        if not all([title, abstract, content, keywords]):
            return jsonify({
                'status': 'error',
                'message': 'All fields are required'
            }), 400

        manuscript = Manuscript(title=title, abstract=abstract, content=content, keywords=keywords, author_id=author_id, status='submitted')
        db.session.add(manuscript)
        db.session.commit()

        # Find suitable reviewers
        # Query for reviewers based on expertise matching with manuscript keywords
        potential_reviewers = User.query.filter(
            User.role == 'reviewer',
            User.id != author_id  # Exclude the author
        ).all()

        if not potential_reviewers:
            return jsonify({
                'status': 'warning',
                'message': 'Manuscript created but no reviewers available'
            }), 200
        
        reviewer = potential_reviewers[0]

        # Create review request
        review = Review(
            manuscript_id=manuscript.id,
            reviewer_id=reviewer.id,
            status='pending'
        )
        db.session.add(review)

        # Create notification for reviewer
        notification = Notification(
            user_id=reviewer.id,
            message=f"You have been assigned to review the manuscript: {manuscript.title}",
            type='review_assigned',
            read=False
        )
        db.session.add(notification)

        # Update manuscript status
        manuscript.status = 'pending_review'
        db.session.commit()

        # Send email notification to reviewer
        if send_review_request_email(reviewer.email, manuscript.title):
            return jsonify({
                'status': 'success',
                'message': 'Manuscript submitted and reviewer assigned successfully',
                'manuscript_id': manuscript.id
            }), 201
        else:
            return jsonify({
                'status': 'warning',
                'message': 'Manuscript submitted but email notification to reviewer failed',
                'manuscript_id': manuscript.id
            }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error creating manuscript: {str(e)}'
        }), 500

    return redirect(url_for('dashboard'))

# Notifications
@app.route('/notifications')
#@login_required
def notifications():
    # Get all notifications for the current user
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.timestamp.desc()).all()
    
    # Mark notifications as read
    for notification in notifications:
        if not notification.is_read:
            notification.is_read = True
    db.session.commit()

    
    return render_template('notifications.html', notifications=notifications)
   # return render_template('notifications.html')   

# route to create review requests
@app.route('/create_review_request/<int:manuscript_id>/<int:reviewer_id>', methods=['POST'])
@login_required
def create_review_request(manuscript_id, reviewer_id):
    try:
        # Get the manuscript and reviewer
        manuscript = Manuscript.query.get_or_404(manuscript_id)
        reviewer = User.query.get_or_404(reviewer_id)
        
        # Create a new review
        review = Review(
            manuscript_id=manuscript_id,
            reviewer_id=reviewer_id,
            status='pending'
        )
        db.session.add(review)
        
        # Create a notification
        notification = Notification(
            user_id=reviewer_id,
            message=f"You have been requested to review the manuscript: {manuscript.title}",
            type='review_assigned',
            read=False
        )
        db.session.add(notification)
        db.session.commit()
        
        # Send email notification
        if send_review_request_email(reviewer.email, manuscript.title):
            return jsonify({
                'status': 'success',
                'message': 'Review request sent successfully'
            }), 200
        else:
            return jsonify({
                'status': 'warning',
                'message': 'Review request created but email notification failed'
            }), 200
            
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# route to get unread notifications count (useful for UI updates)
@app.route('/notifications/unread_count', methods=['GET'])
@login_required
def unread_notifications_count():
    count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()
    return jsonify({'count': count})

# route to assign reviewers
@app.route('/assign_reviewer', methods=['POST'])
@login_required
def assign_reviewer():
    manuscript_id = request.form.get('manuscript_id')
    reviewer_id = request.form.get('reviewer_id')
    
    return create_review_request(manuscript_id, reviewer_id)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)