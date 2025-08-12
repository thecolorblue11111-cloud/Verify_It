from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from models import User
import mfa_utils

auth = Blueprint('auth', __name__)

@auth.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    user = User.get_by_id(session['user_id'])
    if user.mfa_enabled:
        flash("MFA is already enabled.", "info")
        return redirect(url_for('profile'))

    if request.method == 'POST':
        secret = request.form['secret']
        token = request.form['token']
        if mfa_utils.verify_totp(token, secret):
            user.set_mfa(1, secret)
            flash("MFA enabled successfully.", "success")
            return redirect(url_for('profile'))
        else:
            flash("Invalid token. Please try again.", "danger")

    secret = mfa_utils.generate_totp_secret()
    uri = mfa_utils.get_totp_uri(user.username, secret)
    qr_code = mfa_utils.generate_qr_code_base64(uri)
    return render_template('mfa_setup.html', secret=secret, qr_code=qr_code)

@auth.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    if request.method == 'POST':
        token = request.form['token']
        user = User.get_by_id(session['pending_mfa_user'])
        if user and mfa_utils.verify_totp(token, user.mfa_secret):
            session['user_id'] = user.id
            session.pop('pending_mfa_user', None)
            flash("Logged in successfully.", "success")
            return redirect(url_for('profile'))
        else:
            flash("Invalid MFA token.", "danger")
    return render_template('mfa_verify.html')

@auth.route('/mfa/disable', methods=['POST'])
def mfa_disable():
    user = User.get_by_id(session['user_id'])
    user.set_mfa(0, None)
    flash("MFA disabled.", "info")
    return redirect(url_for('profile'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password(user.password_hash, password):
            if user.mfa_enabled:
                session['pending_mfa_user'] = user.id
                return redirect(url_for('auth.mfa_verify'))
            session['user_id'] = user.id
            flash("Logged in successfully.", "success")
            return redirect(url_for('profile'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template('login.html')
