from . import mail
from flask_mail import Message
from flask import url_for


# ################################################
def send_pw_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply.projectbeast@gmail.com',
                  recipients=[user.email])

    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
    
If you did not make this request, then simply ignore this email.
'''

    mail.send(msg)


# ################################################
def send_validation_email(user):
    token = user.get_account_validation_token()
    msg = Message('Email Validation', sender='noreply.projectbeast@gmail.com',
                  recipients=[user.email])

    msg.body = f'''To validate your account, visit the following link:
{url_for('validate_email', token=token, _external=True)}
    
If you did not make this request, then simply ignore this email.
'''

    mail.send(msg)
