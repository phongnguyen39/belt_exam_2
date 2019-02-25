#   Python Belt Exam #2

from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'secret'
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-z0-9.+_-]+@[a-zA-z0-9.+_-]+\.[a-zA-Z]+$')


# REPLACE THE FOLLOWING
# show_all.HTML
# messages ~ comments ~ reviews 


# LOGIN & REGISTRATION HOMEPAGE
@app.route('/')
def index():
    return render_template('index.html')

# REGISTRATION VALIDATIONS
@app.route('/registration', methods=['post'])
def registration():

    # Session Information
    session['first_name'] =request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    session['password'] = request.form['password']

    # print('*'*20,session['first_name'])
    # print('*'*20,session['last_name'])
    # print('*'*20,session['email'])
    # print('*'*20,session['password'])

    is_valid = True

    # Name length validation
    if len(request.form['first_name']) < 3:
        is_valid = False
        # print('*'*20, False, '*'*20)
        flash('Please enter a name that is at least two characters long')
        return redirect('/')

    if len(request.form['last_name']) < 3:
        is_valid = False
        # print('*'*20, False, '*'*20)
        flash('Please enter a name that is at least two characters long')
        return redirect('/')

    # Email format validation
    if not EMAIL_REGEX.match(request.form['email']):
        flash(f"{request.form['email']} is invalid")
        return redirect('/')

    # Existing email validation
    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'SELECT * FROM users WHERE email = %(email)s'
    data = {
        'email': request.form['email']
    }
    existing_email = belt_exam_2.query_db(query, data)
    # print('*'*20,existing_email)
    if len(existing_email) > 0:
        flash('Email already exist.')
        # print(('~'*20))
        return redirect('/')

    # Password length validation
    if len(request.form['password']) < 8:
        is_valid = False
        # print('*'*20, False, '*'*20)
        flash('Please enter a password name that is at least 8 characters long')
        return redirect('/')

    # Password match validation
    if request.form['password'] != request.form['password_conf']:
        is_valid = True
        flash('Make sure your passwords match')
        return redirect('/')

    # Registration Insertion
    if is_valid:
        belt_exam_2 = connectToMySQL('belt_exam_2')
        query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s,%(last_name)s,%(email)s,%(password)s);'
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password': bcrypt.generate_password_hash(request.form['password'])
        }

        users = belt_exam_2.query_db(query, data)
        # print('*----*'*20,users)
        
        flash("You've successfully registered!")

        return redirect('/show_all')


# LOGIN VALIDATIONS
@app.route('/login', methods=['post'])
def login():

    # Session Information
    session['email'] = request.form['email']


    # is_valid = True

    # Email format validation
    if not EMAIL_REGEX.match(request.form['email']):
        flash(f"{request.form['email']} is invalid")
        return redirect('/')

    # Existing email validation
    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'SELECT * FROM users WHERE email = %(email)s'
    data = {
        'email': request.form['email']
    }

    logins = belt_exam_2.query_db(query, data)
    # print(logins,'*/'*30)
    # print('*-*'*20,request.form['email'])
    
    if len(logins) == 0:
        flash("Failed login! Email not found.")
        return redirect('/')

    # Password validation
    if logins:
        if bcrypt.check_password_hash(logins[0]['password'], request.form['password']):
            flash("Logged in successfully!")
            return redirect('/show_all')
        else:
            flash("Failed login! Password was incorrect.")
            return redirect('/')

# show_all PAGE

@app.route('/show_all')
def show_all():

    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'SELECT * FROM users WHERE email = %(email)s;'
    data = {'email' : session['email']}
    users = belt_exam_2.query_db(query,data)
    session['id'] = users[0]['id']

    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'SELECT * FROM users;'
    all_users = belt_exam_2.query_db(query)
    # print('*--*'*30, all_users)

    return render_template('show_all.html', users = users, all_users = all_users)


# INSERTIONS

@app.route('/message', methods = ['post'])
def message():  

    print('*'*20,request.form['message'])
    print('*'*20,session['id'])
    print('*'*20,request.form['receipient'])
    
    #### need to fix foreign key issue on tables

    # Send a message #
    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'INSERT INTO messages (message, sender_id, receipient_id) VALUES (%(message)s, %(sender_id)s,%(receipient_id)s)'
    data = {
        'message': request.form['message'],
        'sender_id': session['id'],
        'receipient_id': request.form['receipient']
    }
    message = belt_exam_2.query_db(query, data)
    print('*'*30, message)
    return redirect('/show_all')

@app.route('/comment', methods = ['post'])
def comment():  
    
    #  Send a comment #
    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'INSERT INTO authors (author_name) VALUES (%(author_name)s)'  #
    data = {
        'author_name': request.form['author_name']
    }
    # = #.query_db(query, data)
    return redirect('/show_all')

# UPDATES

@app.route('/update', methods = ['post'])
def update():  
    
    #  Adds Author
    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'UPDATE database_name SET field_name = "%()s", field_name2 = "%()s" '  #
    data = {
        'author_name': request.form['author_name']
    }
    # = #.query_db(query, data)
    return redirect('/show_all')

# DELETIONS

@app.route('/delete', methods = ['post'])
def delete():  
    
    #  Adds Author
    belt_exam_2 = connectToMySQL('belt_exam_2')
    query = 'DELETE FROM authors (author_name) WHERE  %()s'  #
    data = {
        'author_name': request.form['author_name']
    }
    # = #.query_db(query, data)
    return redirect('/show_all')


# RETURN TO HOME BUTTON

@app.route('/home')
def home():
    return redirect('/')  # CHANGE ME

# LOGOUT BUTTON

@app.route('/logoff')
def logoff():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)