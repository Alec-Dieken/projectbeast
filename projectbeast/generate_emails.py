from . import mail
from flask_mail import Message
from flask import url_for


### Function to send password reset email to the user ###
def send_pw_reset_email(user):
    # Generate reset token
    token = user.get_reset_token()

    # Create message object
    msg = Message('Password Reset Request', sender='noreply.projectbeast@gmail.com',
                  recipients=[user.email])

    # Set message body
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
    
If you did not make this request, then simply ignore this email.
'''

    # Send the message
    mail.send(msg)


### Function to send validation email for email account registration ###
def send_validation_email(user):
    
    # Get unique token from user model
    token = user.get_account_validation_token()
    
    # Create message object
    msg = Message('Email Validation', sender='noreply.projectbeast@gmail.com',
                  recipients=[user.email])
    
    # Set message body
    msg.body = f'''To validate your account, visit the following link:
{url_for('validate_email', token=token, _external=True)}
    
If you did not make this request, then simply ignore this email.
'''

    # Send the message
    mail.send(msg)
