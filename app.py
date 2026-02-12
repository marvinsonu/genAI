from flask import Flask, render_template, request, flash, redirect, url_for, session
from functools import wraps
from controller.config import config
from controller.database import db
from controller.model import User, Role, UserRole
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(config)
app.secret_key = config.SECRET_KEY
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
# ================= LOGIN =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            user_role = UserRole.query.filter_by(user_id=user.user_id).first()

            if user_role:
                # Store user info in session
                session['user_id'] = user.user_id
                session['username'] = user.username
                session['email'] = user.email
                session['role_id'] = user_role.role_id
                
                # Redirect based on role
                if user_role.role_id == 1:
                    flash(f"Welcome Admin {user.username}!", "success")
                    return redirect(url_for('admin_dashboard'))
                elif user_role.role_id == 2:
                    flash(f"Welcome Teacher {user.username}!", "success")
                    return redirect(url_for('teacher_dashboard'))
                elif user_role.role_id == 3:
                    flash(f"Welcome Student {user.username}!", "success")
                    return redirect(url_for('student_dashboard'))
            else:
                flash("User role not assigned", "warning")
        else:
            flash("Invalid Email or Password", "danger")

    return render_template('login.html')


# ================= REGISTER =================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role_id = request.form['role_id']

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists!", "danger")
            return redirect(url_for('register'))

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

        flash("Registration Successful! Please login.", "success")
        return redirect(url_for('login'))

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
@app.route('/teacher-dashboard')
@login_required
def teacher_dashboard():
    if session.get('role_id') != 2:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    username = session.get('username')
    return render_template('teacher_dashboard.html', username=username)


# ================= STUDENT DASHBOARD =================
@app.route('/student-dashboard')
@login_required
def student_dashboard():
    if session.get('role_id') != 3:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))
    
    username = session.get('username')
    return render_template('student_dashboard.html', username=username)

 
if __name__ == '__main__':
    app.run(debug=True)



