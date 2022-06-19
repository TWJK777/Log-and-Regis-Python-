from flask import render_template, request, redirect, session, flash
from flask_app import app
from flask_app.models.log import log
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route( "/" )
def displayLogin():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if not log.validate_registration(request.form):
        return redirect('/')
    
    hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        "first_name" : request.form['first_name'],
        "last_name" : request.form['last_name'],
        "email" : request.form['email'],
        "password" : hash
    }

    user_id = log.save(data)

    session['user_id'] = user_id
    return redirect("/dashboard")

@app.route('/login', methods=['POST'])
def login():
    data = {
        'email' : request.form['email']
    }

    user = log.get_by_email(data)

    validation_data = {
        'user' : user,
        'password' : request.form['password']
    }

    if not log.validate_login(validation_data):
        return redirect('/')
    # if not user:
    #     flash("Invalid Email", "login")
    #     return redirect('/')
    session['user_id'] = user.id
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    data = {
        'user_id' : session['user_id']
    }

    user = log.get_info(data)
    return render_template('show_user.html', user = user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')