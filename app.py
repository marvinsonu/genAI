from flask import Flask, render_template, request, flash, redirect, url_for, session
from functools import wraps
from datetime import timedelta
from controller.config import config
from controller.database import db
from controller.model import User, Role, UserRole, QuizQuestion
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(config)
app.secret_key = config.SECRET_KEY

# Session configuration for "Remember Me" functionality
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db.init_app(app)

# Decorator to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('register'))

with app.app_context():
    db.create_all()

    roles = [
        {"role_id": 1, "name": "Admin"},
        {"role_id": 2, "name": "Teacher"}, 
        {"role_id": 3, "name": "student"}
    ]

    for r in roles:
        existing_role = db.session.get(Role, r["role_id"])
        if not existing_role:
            db.session.add(Role(role_id=r["role_id"], name=r["name"]))

    
    db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember', False)

        # Validate input
        if not email or not password:
            flash("Email and password are required", "danger")
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            user_role = UserRole.query.filter_by(user_id=user.user_id).first()

            if user_role:
                # Store user info in session
                session['user_id'] = user.user_id
                session['username'] = user.username
                session['email'] = user.email
                session['role_id'] = user_role.role_id
                session.permanent = bool(remember_me)  # Make session persistent if "Remember Me" is checked
                
                # Get role name for personalized message
                role = Role.query.get(user_role.role_id)
                role_name = role.name if role else "User"
                
                # Redirect based on role with appropriate dashboard
                if user_role.role_id == 1:
                    flash(f"Welcome back, Admin {user.username}! 👋", "success")
                    return redirect(url_for('admin_dashboard'))
                elif user_role.role_id == 2:
                    flash(f"Welcome back, {user.username}! Ready to teach today? 📚", "success")
                    return redirect(url_for('teacher_dashboard'))
                elif user_role.role_id == 3:
                    flash(f"Welcome back, {user.username}! Let's learn something new! 🎓", "success")
                    return redirect(url_for('student_dashboard'))
            else:
                flash("⚠️ Your account exists but no role is assigned. Please contact support.", "warning")
        else:
            # Provide helpful error message
            if not user:
                flash("❌ No account found with this email address.", "danger")
            else:
                flash("❌ Incorrect password. Please try again.", "danger")

    return render_template('login.html')


# ================= REGISTER =================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmPassword', '')
        role_id = request.form.get('role_id', '')

        # Validation checks
        if not all([name, email, password, confirm_password, role_id]):
            flash("All fields are required", "danger")
            return redirect(url_for('register'))

        if len(name) < 2 or len(name) > 50:
            flash("Name must be between 2 and 50 characters", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))

        if len(password) < 8:
            flash("Password must be at least 8 characters long", "danger")
            return redirect(url_for('register'))

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("📧 This email address is already registered. Please login or use a different email.", "danger")
            return redirect(url_for('register'))

        try:
            # Hash password
            hashed_password = generate_password_hash(password)

            # Create new user
            new_user = User(
                username=name,
                email=email,
                password=hashed_password
            )

            db.session.add(new_user)
            db.session.commit()

            # Assign Role
            user_role = UserRole(
                user_id=new_user.user_id,
                role_id=role_id
            )

            db.session.add(user_role)
            db.session.commit()

            # Get role name for personalized message
            role = Role.query.get(role_id)
            role_name = role.name if role else "User"

            flash(f"✅ Registration successful! Welcome {name}! You're registered as a {role_name}. Please login to continue.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred during registration. Please try again. (Error: {str(e)})", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')


# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


# ================= ADMIN DASHBOARD =================
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if session.get('role_id') != 1:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    # Get all users with their roles
    users = db.session.query(User, UserRole, Role).join(
        UserRole, User.user_id == UserRole.user_id
    ).join(
        Role, UserRole.role_id == Role.role_id
    ).all()
    
    return render_template('admin_dashboard.html', users=users)


# ================= TEACHER DASHBOARD =================
@app.route('/teacher-dashboard', methods=['GET', 'POST'])
@login_required
def teacher_dashboard():
    if session.get('role_id') != 2:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    username = session.get('username')
    user_id = session.get('user_id')

    # Handle creation of simple quiz questions by teacher
    if request.method == 'POST':
        q_text = request.form.get('question', '').strip()
        a = request.form.get('option_a', '').strip()
        b = request.form.get('option_b', '').strip()
        c = request.form.get('option_c', '').strip()
        d = request.form.get('option_d', '').strip()
        correct = request.form.get('correct_answer', '').strip()

        if not all([q_text, a, b, c, d, correct]):
            flash('All fields are required to create a question.', 'danger')
            return redirect(url_for('teacher_dashboard'))

        try:
            # Map selected correct option key to actual option text
            mapping = {
                'option_a': a,
                'option_b': b,
                'option_c': c,
                'option_d': d,
            }
            correct_text = mapping.get(correct, '')

            new_q = QuizQuestion(
                teacher_id=user_id,
                question_text=q_text,
                option_a=a,
                option_b=b,
                option_c=c,
                option_d=d,
                correct_answer=correct_text
            )
            db.session.add(new_q)
            db.session.commit()
            flash('Question created successfully.', 'success')
            return redirect(url_for('teacher_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating question: {e}', 'danger')
            return redirect(url_for('teacher_dashboard'))

    # GET: list questions created by this teacher
    questions = QuizQuestion.query.filter_by(teacher_id=user_id).order_by(QuizQuestion.created_at.desc()).all()
    return render_template('teacher_dashboard.html', username=username, questions=questions)


# ================= STUDENT DASHBOARD =================
@app.route('/student-dashboard')
@login_required
def student_dashboard():
    if session.get('role_id') != 3:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    username = session.get('username')
    return render_template('student_dashboard.html', username=username)


# ================= STUDENT QUIZ ASSESSMENT =================
@app.route('/student-quiz-assessment', methods=['GET', 'POST'])
@login_required
def student_quiz_assessment():
    if session.get('role_id') != 3:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    username = session.get('username')
    # Load questions from DB; fall back to defaults if none exist
    questions_db = QuizQuestion.query.all()
    if questions_db:
        questions = [q.to_dict() for q in questions_db]
    else:
        questions = [
            {
                "id": "q1",
                "question": "What is 12 x 8?",
                "options": ["96", "88", "108", "86"],
                "answer": "96",
            },
            {
                "id": "q2",
                "question": "Which gas do plants absorb from the atmosphere?",
                "options": ["Oxygen", "Carbon Dioxide", "Nitrogen", "Hydrogen"],
                "answer": "Carbon Dioxide",
            },
            {
                "id": "q3",
                "question": "Who wrote Hamlet?",
                "options": ["Charles Dickens", "William Shakespeare", "Jane Austen", "Mark Twain"],
                "answer": "William Shakespeare",
            },
        ]

    score = None
    total = len(questions)
    percentage = None
    selected_answers = {}

    if request.method == 'POST':
        score = 0
        for q in questions:
            student_answer = request.form.get(q["id"], "")
            selected_answers[q["id"]] = student_answer
            if student_answer == q["answer"]:
                score += 1

        percentage = round((score / total) * 100, 2) if total else 0
        flash(f"Quiz submitted. You scored {score}/{total} ({percentage}%).", "success")

    return render_template(
        'student_quiz_assessment.html',
        username=username,
        questions=questions,
        score=score,
        total=total,
        percentage=percentage,
        selected_answers=selected_answers
    )

 
if __name__ == '__main__':
    app.run(debug=True)



