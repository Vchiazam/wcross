from flask_sqlalchemy import SQLAlchemy
from models import db, Question, User, Admin
from auth.admin_auth import *
from auth.admin_reset_auth import *
import bcrypt

# view all questions
def show_questions(response):
    admin_data = response['id']
    questions = Question.query.with_entities(Question.level, Question.question).all()
    quest = {}
    que = []
    for i in questions:
        que.append(i)
        quest.update(que)
    return quest


# create new questions
def new_question(response):
    admin_data = response['id']
    request_data = request.get_json()
    question = request_data.get('question')
    question = question.lower()
    answer = request_data.get('answer')
    answer = answer.lower()
    new_words = request_data.get('new_words')
    new_words = new_words.lower()
    try:
        new_question = Question(question, answer, new_words)
        new_question.insert()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess= 'an error occured')
    finally:
        db.session.close()
    if not error:
        print('New question created')
    return jsonify(
        {
            "mess": 'New Question created'
        }
    )

# gets a specific question by its id
def show_question(response, question_level):
    admin_data = response['id']
    question = Question.query.get(question_level)
    if question == None:
        return jsonify(mess="question with this level was not found")
    return jsonify(
        {
            "question": question.question,
            "answer": question.answer,
            "new_words": question.new_words
        }
    )

#  edit a specific question from the admin
def edit_question(response, question_level):
    admin_data = response['id']
    request_data = request.get_json()
    question = request_data.get('question')
    question = question.lower()
    answer = request_data.get('answer')
    answer = answer.lower()
    new_words = request_data.get('new_words')
    new_words = new_words.lower()
    curr_question = Question.query.get(question_level)
    if curr_question == None:
        return jsonify(mess="question with this level was not found")
    try:
        curr_question = Question.query.get(question_level)
        curr_question.question = question
        curr_question.answer = answer
        curr_question.new_words = new_words
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
            "mess": 'update successful'
        }
    )

# shows admin dashboard
def admin_dashboard(response):
    admin_data = response['id']
    print(admin_data)
    supad = Admin.query.with_entities(Admin.id, Admin.name).all()
    supadm = [x[0] for x in supad]
    supadm = sorted(supadm)
    curr_admin = Admin.query.get(admin_data)
    data = User.query.with_entities(User.id, User.name).all()
    if admin_data == supadm[0]:
       aduser = {
            "curr_admin_name": curr_admin.name,
            "curr_admin_email": curr_admin.email,
            "admin_type": "Superadmin"
        }
    else:
        aduser = {
            "curr_admin_name": curr_admin.name,
            "curr_admin_email": curr_admin.email,
            "admin_type": "Regular"
        }
    user = {}
    users = []
    for i in data:
        users.append(i)
        user.update(users)
    das_data = {"users":user, "admin_user_details":aduser}
    return (das_data)

# view admin user profile
def admin_user_profile(response):
    admin_data = response['id']
    supad = Admin.query.with_entities(Admin.id, Admin.name).all()
    supadm = [x[0] for x in supad]
    supadm = sorted(supadm)
    curr_admin = Admin.query.get(admin_data)
    if admin_data == supadm[0]:
       admin_type = "Superadmin"
    else:
        admin_type = "Regular"
    return jsonify(
        {
            "aduser_name": curr_admin.name,
            "aduser_email": curr_admin.email,
            "aduser_picture": curr_admin.profile_picture,
            "aduser_num": curr_admin.phone_num,
            "admin_type": admin_type
        }
    )


#  edit admin profile
def edit_admin_profile(response):
    admin_data = response['id']
    request_data = request.get_json()
    email = request_data.get('email')
    email = email.lower()
    profile_picture = request_data.get('picture')
    profile_picture = profile_picture.lower()
    phone = request_data.get('phone')
    # rpwd = request_data.get('resetpin')
    # # rpwd = request.form.get('password')
    # rpwd = rpwd.encode('utf-8')
    # salt = bcrypt.gensalt()
    # resetpin = bcrypt.hashpw(rpwd, salt)
    # # print(resetpin)
    # resetpin = str(resetpin)
    # resetpin = resetpin.lstrip("b'")
    # resetpin = resetpin.rstrip("'")
    try:
        curr_admin = Admin.query.get(admin_data)
        curr_admin.name = curr_admin.name
        curr_admin.email = email
        curr_admin.profile_picture = profile_picture
        curr_admin.phone_num = phone
        curr_admin.reset_pin = curr_admin.reset_pin
        curr_admin.password = curr_admin.password
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
            "mess": 'update successful'
        }
    )

# user profile
def user_profile(response, user_id):
    admin_data = response['id']
    cuser = User.query.get(user_id)
    if cuser == None:
        abort(404)
    return jsonify(
        {
            "name": cuser.name,
            "email": cuser.email,
            "phone": cuser.phone_num,
            "picture": cuser.profile_picture,
            "level": cuser.level,
            "new_word": cuser.new_word
        }
    )

#  admin login
def admin_login():
    request_data = request.get_json()
    admin_user = request_data.get('name')
    admin_user = admin_user.lower()
    passw = request_data.get('password')
    admin_data = Admin.query.with_entities(Admin.id, Admin.name, Admin.password).all()
    admin_name = [x[1] for x in admin_data]
    admin_id = [x[0] for x in admin_data]
    admin_password = [x[2] for x in admin_data]
    first = {admin_name[i]: admin_id[i] for i in range(len(admin_name))}
    second = {admin_id[i]: admin_password[i] for i in range(len(admin_name))}
    exist = admin_name.count(admin_user)
    if exist > 0:
        print("admin user found")
        me = first[admin_user]
        mme = second[me]
        mme = str(mme)
        mme = mme.encode()
        bpwd = passw.encode('utf-8')
        lpwd = bcrypt.checkpw(bpwd, mme)
        # print(bpwd)
        if lpwd == True:
            admin_user_id = me
            data = admin_auth(admin_user_id, admin_user)
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

#  admin registration
def admin_register():
    data = Admin.query.with_entities(Admin.id, Admin.name).all()
    radmin = [x[1] for x in data]
    admin_id = [x[0] for x in data]
    admin_id = sorted(admin_id)
    # print(radmin)
    if admin_id == []:
        request_data = request.get_json()
    else:
        admin_access = admin_decode_jwt()
        if admin_access != admin_id[0]:
            return jsonify(mess='Only a Super-admin can register another admin')
        else:
            request_data = request.get_json()
    if request_data == None:
        abort(404)
    else:
        name = request_data.get('name')
    name = name.lower()
    check = radmin.count(name)
    if check >= 1:
        return jsonify(
            {
                "mess": f'An admin account with this user name already exists'
            }
        )
    else:
        rname = name
    rpwd = request_data.get('password')
    # rpwd = request.form.get('password')
    bpwd = rpwd.encode('utf-8')
    salt = bcrypt.gensalt()
    passwor = bcrypt.hashpw(bpwd, salt)
    # print(passwor)
    password = str(passwor)
    password = password.lstrip("b'")
    password = password.rstrip("'")
    email = None
    profile_picture = None
    phone_num = None
    # reset_pin = None
    tpwd = request_data.get('resetpin')
    # rpwd = request.form.get('password')
    if tpwd == None:
        abort(422)
    else:
        tpwd = tpwd.encode('utf-8')
    salt = bcrypt.gensalt()
    resetpin = bcrypt.hashpw(tpwd, salt)
    # print(resetpin)
    resetpin = str(resetpin)
    resetpin = resetpin.lstrip("b'")
    resetpin = resetpin.rstrip("'")
    try:
        admin_user = Admin(rname, email, profile_picture, phone_num, resetpin, password)
        admin_user.insert()
        error = False
    except Exception as e:
        error = True
        print(f'Exception "{e}"')
        db.session.rollback()
        return jsonify(mess="an error occured")
    finally:
        db.session.close()
    if not error:
        print('Admin user created')
        return jsonify(
            {
            "mess": 'Admin registration successful, login to continue'
            }
        )

#  admin forgot password ['GET']
def admin_forgotpassword():
    request_data = request.get_json()
    admin_user = request_data.get('name')
    admin_user = admin_user.lower()
    data = Admin.query.with_entities(Admin.id, Admin.name).all()
    name = [x[1] for x in data]
    user_id = [x[0] for x in data]
    first = {name[i]: user_id[i] for i in range(len(name))}
    exist = name.count(admin_user)
    if exist > 0:
        me = first[admin_user]
        print(me)
        reset_token = admin_reset_auth(me, admin_user)
        return jsonify(reset_token=reset_token)
    else:
        return jsonify(mess="user doesn't exist")

#  admin reset password with token
def admin_resetpassword(token):
    data = admin_reset_decoded_jwt(token)
    request_data = request.get_json()
    resetpin = request_data.get('resetpin')
    newpwd = request_data.get('newpassword')
    cnewpwd = request_data.get('cnewpassword')
    if newpwd != cnewpwd:
        return jsonify(mess='password and confirm password should be the same')
    else:
        curr_admin = Admin.query.get(data)
    reset_pin = curr_admin.reset_pin
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
        curr_admin = Admin.query.get(data)
        curr_admin.name = curr_admin.name
        curr_admin.email = curr_admin.email
        curr_admin.profile_picture = curr_admin.profile_picture
        curr_admin.phone_num = curr_admin.phone_num
        curr_admin.reset_pin = curr_admin.reset_pin
        curr_admin.password = rpassword
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
            "mess": 'admin password reset successful, login to continue'
        }
    )

#  reset admin resetpin
def reset_Admin_resetpin(response):
    adminuser_id = response['id']
    curr_adminuser = Admin.query.get(adminuser_id)
    old_pin = curr_adminuser.reset_pin
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
        curr = Admin.query.get(adminuser_id)
        curr.name = curr.name
        curr.password = curr.password
        curr.email = curr.email
        curr.profile_picture = curr.profile_picture
        curr.phone_num = curr.phone_num
        curr.reset_pin = new_resetpin
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


# create new admin password with yhe former password
def reset_Admin_password(response):
    adminuser_id = response['id']
    curr_adminuser = Admin.query.get(adminuser_id)
    old_password = curr_adminuser.password
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
        curr = Admin.query.get(adminuser_id)
        curr.name = curr.name
        curr.password = new_password
        curr.email = curr.email
        curr.profile_picture = curr.profile_picture
        curr.phone_num = curr.phone_num
        curr.reset_pin = curr.reset_pin
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

