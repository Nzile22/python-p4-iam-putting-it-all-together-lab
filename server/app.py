#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

def format_validation_errors(errors):
    error_messages = []
    for field, messages in errors.items():
        for message in messages:
            error_messages.append(f"{field}: {message}")
    return error_messages

class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            user.password_hash = data.get('password')
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(only=('id', 'username', 'image_url', 'bio')), 201
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username must be unique']}, 422
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'errors': ['Unauthorized']}, 401
        user = User.query.get(user_id)
        if not user:
            return {'errors': ['Unauthorized']}, 401
        return user.to_dict(only=('id', 'username', 'image_url', 'bio')), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get('username')).first()
        if user and user.authenticate(data.get('password')):
            session['user_id'] = user.id
            return user.to_dict(only=('id', 'username', 'image_url', 'bio')), 200
        return {'errors': ['Invalid username or password']}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return '', 204
        return {'errors': ['Unauthorized']}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'errors': ['Unauthorized']}, 401
        recipes = Recipe.query.all()
        recipes_data = []
        for recipe in recipes:
            recipe_dict = recipe.to_dict(only=('id', 'title', 'instructions', 'minutes_to_complete'))
            recipe_dict['user'] = recipe.user.to_dict(only=('id', 'username', 'image_url', 'bio'))
            recipes_data.append(recipe_dict)
        return recipes_data, 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'errors': ['Unauthorized']}, 401
        data = request.get_json()
        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            recipe_dict = recipe.to_dict(only=('id', 'title', 'instructions', 'minutes_to_complete'))
            recipe_dict['user'] = recipe.user.to_dict(only=('id', 'username', 'image_url', 'bio'))
            return recipe_dict, 201
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
