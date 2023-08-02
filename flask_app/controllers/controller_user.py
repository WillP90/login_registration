from flask_app import app
from flask import render_template, redirect, request, session
from flask_app.models.model_user import User
from flask_bcrypt import Bcrypt
from flask import flash
bcrypt = Bcrypt(app)

# Add Routes
# index route
@app.route('/')
def index():
    return redirect('/user/reg_log')

# Registration form route
@app.route('/user/reg_log')
def login_register():
    return render_template('login_reg.html')

# Registration form processing route
@app.route('/process/user', methods=['POST'])
def register_new_user():
    data = {
        "first_name" : request.form['first_name'],
        "last_name" : request.form['last_name'],
        "email" : request.form['email'],
        "password" : request.form['password'],
        "confirm_password" : request.form['confirm_password']
    }
    valid = User.validate_user(data)
    if not valid:
        return redirect('/user/reg_log')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print(pw_hash)
    data['pw_hash'] = pw_hash
    user = User.save_new_user(data)
    session['user_id'] = user
    return redirect(f'/user/{user}')

# User display route
@app.route('/user/<int:id>')
def show_user(id):
    user = User.get_one_by_id(id)
    return render_template('user.html', user = user)

# login processing route
@app.route('/user/login', methods= ['POST'])
def user_login():
    data = {
        'email' : request.form['email']
    }
    user = User.get_user_by_email(data)
    if not user:
        flash("Invalid Email/Password", 'login')
        return redirect('/')
    if not bcrypt.check_password_hash(user.password, request.form['password']):
        flash("Invalid Email/Password", 'login')
        return redirect('/')
    session['user_id'] = user.id
    return redirect(f'/user/{user.id}')

# logout processing route
@app.route('/user/logout')
def logout():
    session.clear()
    return redirect('/')