import os
import logging
import datetime
import functools
from functools import wraps
import jwt
from flask import Flask, jsonify, request, abort
from settings import ADMIN_AUTH
JWT_SECRET = os.environ.get('JWT_SECRET', ADMIN_AUTH)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

class AdminAuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def _logger():
    '''
    Setup logger format, level, and handler.

    RETURNS: log object
    '''
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    log.addHandler(stream_handler)
    return log


LOG = _logger()
LOG.debug("Starting with log level: %s" % LOG_LEVEL )
APP = Flask(__name__)

def requires_admin_auth():
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not 'Authorization' in request.headers:
                abort(401)
            data = request.headers['Authorization']
            token = str.replace(str(data), 'Bearer ', '')
            try:
                response = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            
            except jwt.ExpiredSignatureError:
                raise AdminAuthError({
                    'code': 'token_expired',
                    'description': 'Token expired.'
                }, 401)
            except: # pylint: disable=bare-except
                abort(401)
            return f(response, *args, **kwargs)

        return wrapper
    return requires_auth_decorator

def admin_auth(admin_user_id, admin_user):
    """
    Create JWT token based on email.
    """
    # request_data = request.get_json()
    id = admin_user_id
    password = admin_user
    #email = "dan@gmail.com"
    #password = "1235677"
    if not id:
        LOG.error("No email provided")
        return jsonify({"message": "Missing parameter: email"}, 400)
    if not password:
        LOG.error("No password provided")
        return jsonify({"message": "Missing parameter: password"}, 400)
    body = {'id': id, 'password': password}

    user_data = body
    tokenw =_admin_get_jwt(user_data).decode('utf-8')

    return tokenw

def admin_decode_jwt():
    """
    Check user token and return non-secret data
    """
    if not 'Authorization' in request.headers:
        abort(401)
    data = request.headers['Authorization']
    token = str.replace(str(data), 'Bearer ', '')
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:

            raise AdminAuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)
    except: # pylint: disable=bare-except
        abort(401)


    response = {'id': data['id'],
                'exp': data['exp'],
                'nbf': data['nbf'] }
    curr_user_id = data['id']
    # return jsonify(**response)
    return curr_user_id

def admin_decoded_jwt(token):
    """
    Check user token and return non-secret data
    """
    # if not 'Authorization' in request.headers:
    #     abort(401)
    # data = request.headers['Authorization']
    # token = str.replace(str(data), 'Bearer ', '')
    token = token
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:

            raise AdminAuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

    except: # pylint: disable=bare-except
        abort(401)


    response = {'id': data['id'],
                'exp': data['exp'],
                'nbf': data['nbf'] }
    curr_user_id = data['id']
    # return jsonify(**response)
    return curr_user_id


def _admin_get_jwt(user_data):
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    payload = {'exp': exp_time,
               'nbf': datetime.datetime.utcnow(),
               'id': user_data['id']}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')