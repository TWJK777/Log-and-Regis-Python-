from flask_app.config.mysqlconnection import connectToMySQL
from flask_app import app
from flask import flash
import re
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

class log:
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']

    @staticmethod
    def validate_registration(log):
        is_valid = True 
        if len(log['first_name']) < 2:
            flash("First Name must be at least 2 characters.")
            is_valid = False
        if len(log['last_name']) < 2:
            flash("Last Name must be at least 2 characters.")
            is_valid = False
        if len(log['password']) < 8:
            flash("Password must be 8 or greater.")
            is_valid = False
        if not (log['password'] == log['password confirmation']):
            flash("Password does not match")
            is_valid = False
        if not EMAIL_REGEX.match(log['email']): 
            flash("Invalid email address!")
            is_valid = False
        return is_valid

    @staticmethod
    def validate_login(log):
        is_valid = True
        if not log['user']:
            flash("invalid email/pword")
            is_valid = False
        elif not bcrypt.check_password_hash(log['user'].password, log['password']):
            flash("invalid email/pword")
            is_valid = False
        return is_valid

    @classmethod
    def save(cls, data):
        query = 'insert into logs (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);'
        results = connectToMySQL('log_reg_schema').query_db(query, data)
        return results

    @classmethod
    def get_info(cls, data):
        query = 'select * from logs where id = %(user_id)s'
        result = connectToMySQL('log_reg_schema').query_db(query, data)
        if len(result) < 1:
            return False
        return cls(result[0])

    @classmethod
    def get_by_email(cls, data):
        query = 'select * from logs where email = %(email)s'
        result = connectToMySQL('log_reg_schema').query_db(query, data)
        if len(result) < 1:
            return False
        return cls(result[0])