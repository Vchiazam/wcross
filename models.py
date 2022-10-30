import os
from flask_sqlalchemy import SQLAlchemy
from settings import DB_NAME, DB_USER_AND_PASSWORD, DB_HOST
db = SQLAlchemy()

database_path = "postgresql://{}@{}/{}".format (DB_USER_AND_PASSWORD, DB_HOST, DB_NAME)

class Question(db.Model):
    __tablename__ = 'question'
    
    level = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String,nullable=False)
    answer = db.Column(db.String,nullable=False)
    new_words = db.Column(db.String,nullable=False)
    
    def __init__(self, question, answer, new_words):
        self.question = question
        self.answer = answer
        self.new_words = new_words
    
    def __repr__(self):
        return f'<Question {self.level} {self.question} {self.answer} {self.new_words}'

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'level': self.level,
            'question': self.question,
            'answer': self.answer,
            'new_words': self.new_words
            }
    

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String,nullable=False)
    email = db.Column(db.String,nullable=True)
    profile_picture = db.Column(db.String,nullable=True)
    phone_num = db.Column(db.String, nullable = True)
    reset_pin = db.Column(db.String, nullable = True)
    password = db.Column(db.String,nullable=False)
    level = db.Column(db.Integer, nullable = False)
    new_words = db.Column(db.String,nullable=True)
    answer = db.Column(db.String,nullable=True)
    new_word = db.Column(db.Integer,nullable=False)
    
    
    def __init__(self, name, email, profile_picture, phone_num, reset_pin, password, level,  new_words, answer, new_word):
        self.name = name
        self.email = email
        self.profile_picture = profile_picture
        self.phone_num = phone_num
        self.reset_pin = reset_pin
        self.password = password
        self.level = level
        self.new_words = new_words
        self.answer = answer
        self.new_word = new_word

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'name': self.name,
            'email': self.email,
            'picture': self.profile_picture,
            'phone': self.phone_num,
            'level': self.level,
            'new_word': self.new_word
            }
    def __repr__(self):
        return f'({self.id}, "{self.name}", {self.password})'

class Admin(db.Model):
    __tablename__ = 'admin'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String,nullable=False)
    email = db.Column(db.String,nullable=True)
    profile_picture = db.Column(db.String,nullable=True)
    phone_num = db.Column(db.String, nullable = True)
    reset_pin = db.Column(db.String, nullable = False)
    password = db.Column(db.String,nullable=False)

    def __init__(self, name, email, profile_picture, phone_num, reset_pin, password):
        self.name = name
        self.email = email
        self.profile_picture = profile_picture
        self.phone_num = phone_num
        self.reset_pin = reset_pin
        self.password = password
    
    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()