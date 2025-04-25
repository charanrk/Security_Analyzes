from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from ..models import db, User
import jwt
import os
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.index'))
        
        flash('Invalid email or password')
    
    return render_template('auth/login.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists')
            return redirect(url_for('auth.signup'))
        
        new_user = User(
            email=email,
            password=generate_password_hash(password),
            name=name
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('main.index'))
    
    return render_template('auth/signup.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@auth_bp.route('/api/token', methods=['POST'])
def get_token():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Unauthorized'}), 401
    
    token = jwt.encode(
        {
            'user_id': current_user.id,
            'exp': datetime.utcnow() + timedelta(days=1)
        },
        os.getenv('JWT_SECRET', 'your-secret-key-here'),
        algorithm='HS256'
    )
    
    return jsonify({'token': token}) 