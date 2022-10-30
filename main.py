from flask import Flask, render_template, render_template, request, redirect, session, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import logging
import datetime
import functools
import jwt
import bcrypt
from flask_cors import CORS
from auth.auth import *
from auth.reset_auth import *
from models import db, Question, User, Admin
from models import database_path
from admin.admin import *
from sqlalchemy import tuple_

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = database_path
db.init_app(app)
db.app = app
db.create_all()
cors = CORS(app)
# CORS(app, resources={'/': {'origins': '*'}})

# @app.after_request
# def after_request(response):
#     response.headers.add(
#         "Access-Control-Allow-Headers", "Content-Type,Authorization,true"
#     )
#     response.headers.add(
#         "Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS"
#     )
#     return response

#  home page
@app.route('/')
def home():
    # return render_template('index.html')
    return jsonify(
        {
            "mess": "Welcome to w cross. built by creast studio"
        }
    )

# view all questions
@app.route('/admin/question')
@requires_admin_auth()
def shows_questions(response):
    data = show_questions(response)
    return data

# create new questions
@app.route('/admin/question', methods=['POST'])
@requires_admin_auth()
def create_question(response):
    data = new_question(response)
    return data

# view a particular question
@app.route('/admin/question/<int:question_level>')
@requires_admin_auth()
def get_question(response, question_level):
    data = show_question(response, question_level)
    return data

#  edit a specific question from the admin
@app.route('/admin/question/<int:question_level>', methods=['POST'])
@requires_admin_auth()
def update_question(response, question_level):
    data = edit_question(response, question_level)
    return data


# view admin dashboard
@app.route('/admin/dashboard')
@requires_admin_auth()
def get_admin_dashboard(response):
    data = admin_dashboard(response)
    return data
    

#  view admin user profile
@app.route('/admin/profile')
@requires_admin_auth()
def get_admin_user_profile(response):
    data = admin_user_profile(response)
    return data


#  edit admin user profile
@app.route('/admin/profile', methods=['POST']) 
@requires_admin_auth()
def update_admin_profile(response):
    data = edit_admin_profile(response)
    return data
        

#  view a specific user profile and their details
@app.route('/admin/users/profile/<int:user_id>')
@requires_admin_auth()
def get_user_profile(response, user_id):
    data = user_profile(response, user_id)
    return data

#  reset admin resetpin with the current resetpin
@app.route('/admin/account/resetpin', methods=['POST'])
@requires_admin_auth()
def get_reset_Admin_resetpin(response):
    data = reset_Admin_resetpin(response)
    return data


#  reset admin user password with the current password
@app.route('/admin/account/password', methods=['POST'])
@requires_admin_auth()
def get_reset_Admin_password(response):
    data = reset_Admin_password(response)
    return data


# user dashboard
@app.route('/dashboard')
@requires_auth()
def dashboard(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    cprofile = curr_user.reset_pin
    if cprofile == None:
        cp = "not created"
    else:
        cp = "created"
    return jsonify(
            {
                "level": curr_user.level,
                "user": curr_user.name,
                "new words": curr_user.new_word,
                "popup": cp
            }
        )


#  login dashboard with toke and user_id
@app.route('/login_dashboard/<int:user_id>/<token>')
def login_dashboard(user_id, token):
    data = decoded_jwt(token)
    if data == user_id:
        cuser_id = data
    else:
        abort(401)
    curr_user = User.query.get(cuser_id)
    return jsonify(
            {
                "level": curr_user.level,
                "user": curr_user.name,
                "new words": curr_user.new_word,
                "token": token
            }
        )

#  admin login
@app.route('/admin/login', methods=['POST'])
def get_admin_login():
    data = admin_login()
    return data


#  user login
@app.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()
    user_name = request_data.get('name')
    user_name = user_name.lower()
    passw = request_data.get('password')
    data = User.query.with_entities(User.id, User.name, User.password).all()
    name = [x[1] for x in data]
    id = [x[0] for x in data]
    password = [x[2] for x in data]
    first = {name[i]: id[i] for i in range(len(name))}
    second = {id[i]: password[i] for i in range(len(name))}
    exist = name.count(user_name)
    if exist > 0:
        print("user found")
        me = first[user_name]
        mme = second[me]
        mme = str(mme)
        mme = mme.encode()
        # print(mme)
        bpwd = passw.encode('utf-8')
        lpwd = bcrypt.checkpw(bpwd, mme)
        # print(bpwd)
        if lpwd == True:
            user_id = me
            data = auth(me, user_name)
            # return redirect(url_for('login_dashboard', user_id=user_id, token=data))
            return jsonify(
                {
                    "token": data,
                    "success": True
                }
            )
        else:
            return jsonify(
                {
                    "mess": "wrong password"
                }
            )
    else:
        return jsonify(
            {
                "mess": "user doesn't exist"
            }
        )
    return f'pass'

#  admin reegistration
@app.route('/admin/register', methods=['POST'])
def get_admin_register():
    data = admin_register()
    return data

#  user registration
@app.route('/register', methods=['POST'])
def sign_up():
    data = User.query.with_entities(User.name).all()
    euser = [x[0] for x in data]
    # print(euser)
    request_data = request.get_json()
    if request_data == None:
        abort(404)
    else:
        iname = request_data.get('name')
    iname = iname.lower()
    check = euser.count(iname)
    if check >= 1:
        return jsonify(
            {
                "mess": f'An account with this user name already exists'
            }
        )
    else:
        name = iname
    rpwd = request_data.get('password')
    # rpwd = request.form.get('password')
    bpwd = rpwd.encode('utf-8')
    salt = bcrypt.gensalt()
    passwor = bcrypt.hashpw(bpwd, salt)
    # print(passwor)
    password = str(passwor)
    password = password.lstrip("b'")
    password = password.rstrip("'")
    level = 1
    new_words = None
    answer = None
    email = None
    profile_picture = None
    phone_num = None
    reset_pin = None
    new_word = 0
    try:
        user = User(name, email, profile_picture, phone_num, reset_pin, password, level,  new_words, answer, new_word)
        user.insert()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('New user created')
    return jsonify(
        {
            "mess": 'registration successful, login to continue'
        }
    )

#  user requesting for reset of password
@app.route('/forgotpassword', methods=['POST'])
def forgotpassword():
    request_data = request.get_json()
    user_name = request_data.get('name')
    user_name = user_name.lower()
    data = User.query.with_entities(User.id, User.name).all()
    name = [x[1] for x in data]
    id = [x[0] for x in data]
    first = {name[i]: id[i] for i in range(len(name))}
    exist = name.count(user_name)
    if exist > 0:
        print("user found")
        me = first[user_name]
        curr_user = User.query.get(me)
        rpwd = curr_user.reset_pin
        if rpwd == None:
            return jsonify(mess='No resetpin was set for this User, try logging instead')
        else:
            data = reset_auth(me, user_name)
            return jsonify(token=data)
    else:
        return jsonify(mess='username does not exist')

#  reseting user password with an existing resetpin 
@app.route('/forgotpassword/<token>', methods=['POST'])
def resetpassword(token):
    data = reset_decoded_jwt(token)
    request_data = request.get_json()
    resetpin = request_data.get('resetpin')
    newpwd = request_data.get('newpassword')
    cnewpwd = request_data.get('cnewpassword')
    if newpwd != cnewpwd:
        return jsonify(mess='password and confirm password should be the same')
    else:
        curr_user = User.query.get(data)
    reset_pin = curr_user.reset_pin
    bpwd = resetpin.encode('utf-8')
    reset_pin = reset_pin.encode()
    lpwd = bcrypt.checkpw(bpwd, reset_pin)
    if lpwd != True:
        return jsonify(mess="wrong resetpin")
    else:
        brpwd = newpwd.encode('utf-8')
    salt = bcrypt.gensalt()
    passwor = bcrypt.hashpw(brpwd, salt)
    # print(passwor)
    password = str(passwor)
    password = password.lstrip("b'")
    rpassword = password.rstrip("'")
    try:
        curr_user = User.query.get(data)
        curr_user.level = curr_user.level
        curr_user.new_words = curr_user.new_words
        curr_user.answer = curr_user.answer
        curr_user.email = curr_user.email
        curr_user.profile_picture = curr_user.profile_picture
        curr_user.phone_num = curr_user.phone_num
        curr_user.reset_pin = curr_user.reset_pin
        curr_user.new_word = curr_user.new_word
        curr_user.name = curr_user.name
        curr_user.password = rpassword
        db.session.commit()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('updated')
    return jsonify(
        {
            "mess": 'password reset successful, login to continue'
        }
    )

# Create reset pin
@app.route('/create/resetpin', methods=['POST'])
@requires_auth()
def create_resetpin(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    old_pin = curr_user.reset_pin
    if old_pin != None:
        return jsonify(mess="This user has already set a reset pin before")
    request_data = request.get_json()
    if request_data == None:
        abort(400)
    rpwd = request_data.get('resetpin')
    # rpwd = request.form.get('password')
    rpwd = rpwd.encode('utf-8')
    salt = bcrypt.gensalt()
    resetpin = bcrypt.hashpw(rpwd, salt)
    # print(resetpin)
    resetpin = str(resetpin)
    resetpin = resetpin.lstrip("b'")
    resetpin = resetpin.rstrip("'")
    try:
        curr = User.query.get(user_id)
        curr.name = curr.name
        curr.password = curr.password
        curr.email = curr.email
        curr.profile_picture = curr.profile_picture
        curr.phone_num = curr.phone_num
        curr.reset_pin = resetpin
        curr.level = curr.level
        curr.new_words = curr.new_words
        curr.answer = curr.answer
        curr.new_word = curr.new_word
        db.session.commit()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('Updated')
        return jsonify(mess='your reset pin has been created')


#  reset your resetpin
@app.route('/account/resetpin', methods=['POST'])
@requires_auth()
def reset_resetpin(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    old_pin = curr_user.reset_pin
    request_data = request.get_json()
    if request_data == None:
        abort(400)
    former_resetpin = request_data.get('formerresetpin')
    new_resetpin = request_data.get('newresetpin')
    cnew_resetpin = request_data.get('cnewresetpin')
    if old_pin == None:
        return jsonify(mess="no resetpin as been set for this user")
    if new_resetpin != cnew_resetpin:
        return jsonify(mess="new and confirm resetpin must be the same")
    old_pin = old_pin.encode()
    # print(mme)
    former_resetpin = former_resetpin.encode('utf-8')
    check = bcrypt.checkpw(former_resetpin, old_pin)
    if check == False:
        return jsonify(mess="wrong resetpin")
    new_resetpin = new_resetpin.encode('utf-8')
    salt = bcrypt.gensalt()
    new_resetpin = bcrypt.hashpw(new_resetpin, salt)
    # print(resetpin)
    new_resetpin = str(new_resetpin)
    new_resetpin = new_resetpin.lstrip("b'")
    new_resetpin = new_resetpin.rstrip("'")
    try:
        curr = User.query.get(user_id)
        curr.name = curr.name
        curr.password = curr.password
        curr.email = curr.email
        curr.profile_picture = curr.profile_picture
        curr.phone_num = curr.phone_num
        curr.reset_pin = new_resetpin
        curr.level = curr.level
        curr.new_words = curr.new_words
        curr.answer = curr.answer
        curr.new_word = curr.new_word
        db.session.commit()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('Updated')
        return jsonify(mess='your reset pin has been updated')


#  create a new password 
@app.route('/account/password', methods=['POST'])
@requires_auth()
def reset_password(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    old_password = curr_user.password
    request_data = request.get_json()
    if request_data == None:
        abort(400)
    former_password = request_data.get('formerpassword')
    new_password = request_data.get('newpassword')
    cnew_password = request_data.get('cnewpassword')
    if new_password != cnew_password:
        return jsonify(mess="new and confirm password must be the same")
    old_password = old_password.encode()
    # print(mme)
    former_password = former_password.encode('utf-8')
    check = bcrypt.checkpw(former_password, old_password)
    if check == False:
        return jsonify(mess="wrong password")
    new_password = new_password.encode('utf-8')
    salt = bcrypt.gensalt()
    new_password = bcrypt.hashpw(new_password, salt)
    # print(resetpin)
    new_password = str(new_password)
    new_password = new_password.lstrip("b'")
    new_password = new_password.rstrip("'")
    try:
        curr = User.query.get(user_id)
        curr.name = curr.name
        curr.password = new_password
        curr.email = curr.email
        curr.profile_picture = curr.profile_picture
        curr.phone_num = curr.phone_num
        curr.reset_pin = curr.reset_pin
        curr.level = curr.level
        curr.new_words = curr.new_words
        curr.answer = curr.answer
        curr.new_word = curr.new_word
        db.session.commit()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('Updated')
        return jsonify(mess='your password has been updated')


#  admin forgotpassword
@app.route('/admin/forgotpassword', methods=['POST'])
def get_admin_forgotpassword():
    data = admin_forgotpassword()
    return data
    

#  admin reset password
@app.route('/admin/forgotpassword/<token>', methods=['POST'])
def get_admin_resetpassword(token):
    data = admin_resetpassword(token)
    return data


# user profile
@app.route('/profile', methods=['GET'])
@requires_auth()
def view_profile(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    profile_data = curr_user.format()
    self = User.query.get(user_id)
    if curr_user.reset_pin == None:
        reset = "none"
    else:
        reset = "active"
    data = {
            'name': self.name,
            'email': self.email,
            'picture': self.profile_picture,
            'phone': self.phone_num,
            'level': self.level,
            'new_word': self.new_word,
            'reset': reset
            }
    return data

# edit user profile
@app.route('/profile', methods=['POST'])
@requires_auth()
def profile(response):
    user_id = response['id']
    request_data = request.get_json()
    if request_data == None:
        abort(400)
    else:
        profile_data = request_data
    # rpwd = request_data.get('resetpin')
    # # rpwd = request.form.get('password')
    # rpwd = rpwd.encode('utf-8')
    # salt = bcrypt.gensalt()
    # resetpin = bcrypt.hashpw(rpwd, salt)
    # # print(resetpin)
    # resetpin = str(resetpin)
    # resetpin = resetpin.lstrip("b'")
    # resetpin = resetpin.rstrip("'")
    phone = profile_data.get('phone')
    try:
        curr = User.query.get(user_id)
        curr.name = curr.name
        curr.password = curr.password
        curr.email = profile_data.get('email')
        curr.profile_picture = profile_data.get('picture')
        curr.phone_num = phone
        curr.reset_pin = curr.reset_pin
        curr.level = curr.level
        curr.new_words = curr.new_words
        curr.answer = curr.answer
        curr.new_word = curr.new_word
        db.session.commit()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('Updated')
        return jsonify(mess='updated')


#  delete user account
@app.route('/account/delete', methods=['POST'])
@requires_auth()
def delete(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    if curr_user == None:
        return jsonify(mess="this account doesn't exist in our server")
    try:
        curr_user = User.query.get(user_id)
        curr_user.delete()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured, account could not be deleted')
    finally:
        db.session.close()
    if not error:
        print('Account deleted')
        return jsonify(mess='Account succefully deleted')


@app.route('/completed')
@requires_auth()
def completed(response):
        user_id = response['id']
        curr_user = User.query.get(user_id)
        if curr_user == None:
            return f'wrong url'
        level = Question.query.get(curr_user.level)
        if curr_user.level > 1:
            past_level = curr_user.level - 1
            question = level.question
            return jsonify(
                {
                    "completed": f'congratulations {curr_user.name} you have finished level {past_level}.',
                    "number of new words": curr_user.new_word
                }
            )
        else:
            return 'wrong url'

@app.route('/game', methods=['GET'])
@requires_auth()
def games(response):
    user_id = response['id']
    curr_user = User.query.get(user_id)
    level = Question.query.get(curr_user.level)
    new_word = curr_user.new_word
    question = level.question
    format_level_answer = level.answer
    format_level_answer = format_level_answer.split(" ")
    level_answers = list(format_level_answer)
    format_answer = curr_user.answer
    if format_answer == None:
        format_answer = []
    else:
        format_answer = format_answer.split(" ")
    answers = list(format_answer)
    format_new_words = curr_user.new_words
    if format_new_words == None:
        format_new_words = []
    else:
        format_new_words = format_new_words.split(" ")
    new_words = list(format_new_words)
    cnew = len(new_words)
    num = len(level_answers) - len(answers)
    return jsonify(
            { 
                "success": True,
                "question": question,
                "level": curr_user.level,
                "new_words": curr_user.new_word,
                "list": answers,
                "number of words remaining": num,
                "number of new words found": cnew

            }
        )
    # return data
@app.route("/game", methods=['POST'])
@requires_auth()
def index(response):
        user_id = response['id']
        request_data = request.get_json()
        if request_data == None:
            abort(400)
        else:
            word = request_data.get('word')
        curr_user = User.query.get(user_id)
        level = Question.query.get(curr_user.level)
        question = level.question
        format_answer = level.answer
        format_answer = format_answer.split(" ")
        answers = list(format_answer)
        format_new_words = level.new_words
        format_new_words = format_new_words.split(" ")
        new_words = list(format_new_words)
        wordss = curr_user.answer
        if wordss == None:
            words = []
        else:
            wordss = wordss.split(" ")
            words = list(wordss)
        newlys = curr_user.new_words
        if newlys == None:
            newly = []
        else:
            newlys = newlys.strip()
            newly = newlys.split(" ")
        til = ''
        nk = len(answers) - len(words)
        count = answers.count(word)
        county = new_words.count(word)
        recou = words.count(word)
        neww = newly.count(word)
        cnew = curr_user.new_word
        if recou > 0:
            messs = f"{word} has been added before, try again"
            dd = words
            num = len(answers) - len(words)
        if count > 0 and recou <= 0:
            words.append(word)
            git = len(newly)
            til = ' '.join(words)
            try:
                    curr = User.query.get(user_id)
                    curr.name = curr.name
                    curr.password = curr.password
                    curr.level = curr.level
                    curr.new_words = curr.new_words
                    curr.answer = til
                    curr.new_word = curr.new_word
                    db.session.commit()
                    error = False
            except Exception as e:
                    error = True
                    print(f'Exception "{e}"')
                    db.session.rollback()
                    return jsonify(mess= 'an error occured')
            finally:
                    db.session.close()
            if not error:
                    print('Updated')
            messs = "correct"
            dd = words
            num = len(answers) - len(words)
            if len(answers) - len(words) == 0:
                messs = "Congratulations, level completed"
                dd = words
                num = "completed"
                git = len(newly)
                try:
                    curr = User.query.get(user_id)
                    curr.name = curr.name
                    curr.password = curr.password
                    curr.level = curr.level + 1
                    curr.new_words = None
                    curr.answer = None
                    curr.new_word = curr.new_word
                    db.session.commit()
                    error = False
                except Exception as e:
                    error = True
                    print(f'Exception "{e}"')
                    db.session.rollback()
                    return jsonify(mess= 'an error occured')
                finally:
                    db.session.close()
                if not error:
                    # ni.append(1)
                    print('Updated')
                    # return redirect(url_for('completed'))
        if neww > 0:
            git = len(newly)
            messs = f'this new word has been found before, try again, you have found {git} new words'
            dd = words
            num = len(answers) - len(words)
        if county > 0 and neww <= 0:
            newly.append(word)
            git = len(newly)
            nw = ' '.join(newly)
            try:
                    curr = User.query.get(user_id)
                    curr.name = curr.name
                    curr.password = curr.password
                    curr.level = curr.level
                    curr.new_words = nw
                    curr.answer = curr.answer
                    curr.new_word = curr.new_word + 1
                    db.session.commit()
                    error = False
            except Exception as e:
                    error = True
                    print(f'Exception "{e}"')
                    db.session.rollback()
                    return jsonify(mess= 'an error occured')
            finally:
                    db.session.close()
            if not error:
                    print('Updated')
            messs = f'{word} is a new word, try again'
            git = len(newly)
            dd = words
            num = len(answers) - len(words)
            cnew = cnew + 1
        if county <= 0 and count <= 0:
            messs = "try again"
            dd = None
            num = len(answers) - len(words)
            if len(words) > 0:
                dd = words
    
        return jsonify(
            { 
                "success": True,
                "list": dd,
                "message": messs,
                "number of words remaining": num,
                "number of new words found": cnew,
                "last input": word
            }
        )
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": 'Unathorized'
    }), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404

@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422

@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['description']
    }), error.status_code

@app.errorhandler(ResetAuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['description']
    }), error.status_code

@app.errorhandler(AdminResetAuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['description']
    }), error.status_code

@app.errorhandler(AdminAuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['description']
    }), error.status_code

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": 'Unathorized'
    }), 401


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": 'Internal Server Error'
    }), 500


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": 'Bad Request'
    }), 400


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": 'Method Not Allowed'
    }), 405