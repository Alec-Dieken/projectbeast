import re
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, HiddenField, SelectMultipleField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from projectbeast.models import Users
from flask_login import current_user


class NonValidatingSelectMultipleField(SelectMultipleField):
    def pre_validate(self, form):
        pass


# ######################################### SIGNUP FORM ####################################################
# ##########################################################################################################
class SignupForm(FlaskForm):

    email = StringField('Email',
        validators=[DataRequired(message='You must provide a valid email.'),
                    Email(message='You must provide a valid email.'), Length(max=254)])

    confirm_email = StringField('Confirm Email',
        validators=[EqualTo('email', message='Emails must match.'), Length(max=254)])

    password = PasswordField('Password',
        validators=[DataRequired(message='You must provide a password.'),
                    Length(min=8, message='Password must be at least 8 characters long.'),
                    Length(max=64, message="Password can't be more than 64 characters long.")])

    confirm_password = PasswordField('Confirm Password',
        validators=[EqualTo('password', message='Passwords must match.'), Length(max=64)])

    username = StringField('Username',
        validators=[DataRequired(message='You must choose a username.'),
                    Length(min=3, message='Username must be at least 3 characters long.'),
                    Length(max=24, message="Username can't be more than 24 characters long.")])

    firstname = StringField('First Name',
        validators=[DataRequired(message='You must provide a first name.'),
                    Length(min=1, max=50, message="First name can't be more than 50 characters long.")])

    lastname = StringField('Last Name (optional)',
        validators=[Length(max=50, message="Last name can't be more than 50 characters long.")])

    terms = BooleanField('Terms', validators=[DataRequired(
        message="You must accept the terms and conditions.")])

    submit = SubmitField('Create Account')


    # ################################################
    def validate_username(self, username):
        result = re.fullmatch(r'([0-9A-Za-z_])\w+', username.data)
        if Users.query.filter_by(username=username.data).first():
            raise ValidationError(
                'That username is already taken. Please choose another.')
        if result is None:
            raise ValidationError(
                'Username can only contain letters, numbers, and underscores.')

    # ################################################
    def validate_email(self, email):
        if Users.query.filter_by(email=email.data).first():
            raise ValidationError(
                'That email is already taken. Please choose another.')

    # ################################################
    def validate_firstname(self, firstname):
        result = re.fullmatch(r'([A-Za-z -])\w+', firstname.data)
        if result is None:
            raise ValidationError(
                'First name can only contain letters, spaces, and hyphens.')

    # ################################################
    def validate_lastname(self, lastname):
        result = re.fullmatch(r'([A-Za-z -])\w+', lastname.data)
        if result is None:
            raise ValidationError(
                'Last name can only contain letters, spaces, and hyphens.')


# ######################################### LOGIN FORM #####################################################
# ##########################################################################################################
class LoginForm(FlaskForm):
    email = StringField('Email',
        validators=[DataRequired(), Email(), Length(max=254)])

    password = PasswordField('Password',
        validators=[DataRequired(), Length(min=8, max=64)])

    remember = BooleanField('Remember Me')

    submit = SubmitField('Login')


# ######################################### REQUEST RESET FORM #############################################
# ##########################################################################################################
class RequestResetForm(FlaskForm):
    email = StringField('Email',
        validators=[DataRequired(), Email(), Length(max=254)])

    submit = SubmitField('Send Email')


# ##################################### RESET PASSWORD FORM ################################################
# ##########################################################################################################
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password',
        validators=[DataRequired()])

    confirm_password = PasswordField('Confirm Password',
        validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Save Password')


# ######################################### ADD PROJECT FORM ###############################################
# ##########################################################################################################
class AddProjectForm(FlaskForm):
    project_name = StringField('Project Name',
        validators=[DataRequired(), Length(min=1, max=50)])

    description = StringField('Description',
         validators=[Length(min=1, max=500)])

    group_id = SelectField('Group')

    submit = SubmitField('Create Project')


# #################################### ADD PROJECT NO GROUP FORM ###########################################
# ##########################################################################################################
class AddProjectFormNoGroup(FlaskForm):
    group_id = HiddenField()

    project_name = StringField('Project Name',
        validators=[DataRequired(), Length(min=1, max=50)])

    description = StringField('Description',
        validators=[Length(min=1, max=500)])

    submit = SubmitField('Create Project')


# ######################################### ADD TASK FORM ##################################################
# ##########################################################################################################
class AddTaskForm(FlaskForm):
    task_name = StringField('Task Name',
        validators=[DataRequired(), Length(min=1, max=50)])

    description = StringField('Description',
        validators=[Length(min=1, max=500)])

    priority = SelectField('Priority',
        validators=[])

    type = SelectField('Type',
        validators=[])

    project_id = SelectField('Project')

    submit = SubmitField('Create Task')
    
    
# ######################################## ADD TASK NO PROJECT FORM ########################################
# ##########################################################################################################
class AddTaskFormNoProject(FlaskForm):
    project_id = HiddenField()
    
    task_name = StringField('Task Name',
        validators=[DataRequired(), Length(min=1, max=50)])

    description = StringField('Description',
        validators=[Length(min=1, max=500)])

    priority = SelectField('Priority',
        validators=[])

    type = SelectField('Type',
        validators=[])

    submit = SubmitField('Create Task')


# ######################################### ADD GROUP FORM #################################################
# ##########################################################################################################
class AddGroupForm(FlaskForm):
    group_name = StringField('Group Name',
        validators=[DataRequired(message="You must choose a name for your group."),
                    Length(max=24, message="Length of group name can't be more than 24 characters.")])

    submit = SubmitField('Create Group')


    # ################################################
    def validate_group_name(self, group_name):
        result = re.fullmatch(r'([0-9A-Za-z- ~_.])+', group_name.data)
        if result is None:
            raise ValidationError(
                'Group name can only include, letters, numbers, spaces, and special characters: _ . ~ -')


# ####################################### ADD GROUP MEMBER FORM ############################################
# ##########################################################################################################
class AddGroupMemberForm(FlaskForm):
    peers = NonValidatingSelectMultipleField('Peers',
        validators=[DataRequired()])

    submit = SubmitField('Send Invites')


# ######################################## EDIT ACCOUNT FORM ###############################################
# ##########################################################################################################
class EditAccountForm(FlaskForm):
    firstname = firstname = StringField('First Name',
        validators=[DataRequired(message='You must provide a first name.'),
                    Length(min=1, max=50, message="First name can't be more than 50 characters long.")])

    lastname = StringField('Last Name (optional)',
        validators=[Length(max=50, message="Last name can't be more than 50 characters long.")])

    username = StringField('Username',
        validators=[DataRequired(message='You must choose a username.'),
                    Length(min=3, message='Username must be at least 3 characters long.'),
                    Length(max=24, message="Username can't be more than 24 characters long.")])

    bio = TextAreaField()

    submit = SubmitField('Save Info')


    # ################################################
    def validate_firstname(self, firstname):
        result = re.fullmatch(r'([A-Za-z -])\w+', firstname.data)
        if result is None:
            raise ValidationError(
                'First name can only contain letters, spaces, and hyphens.')

    # ################################################
    def validate_lastname(self, lastname):
        result = re.fullmatch(r'([A-Za-z -])\w+', lastname.data)
        if result is None:
            raise ValidationError(
                'Last name can only contain letters, spaces, and hyphens.')

    # ################################################
    def validate_username(self, username):
        result = re.fullmatch(r'([0-9A-Za-z_])\w+', username.data)
        if Users.query.filter_by(username=username.data).first() and username.data != current_user.username:
            raise ValidationError(
                'That username is already taken. Please choose another.')
        if result is None:
            raise ValidationError(
                'Username can only contain letters, numbers, and underscores.')


# ####################################### UPLOAD IMAGE FORM ################################################
# ##########################################################################################################
class UploadImage(FlaskForm):
    upload = FileField('Image',
        validators=[FileRequired(message="Please upload a valid picture."),
                    FileAllowed(['jpg', 'jpeg', 'png'], message="Only jpg's and png's allowed.")])

    submit = SubmitField('Upload Image')


# ####################################### EDIT GROUP FORM ##################################################
# ##########################################################################################################
class EditGroupForm(FlaskForm):
    group_name = StringField('Group Name',
        validators=[DataRequired(message="You must choose a name for your group."),
                    Length(max=24, message="Length of group name can't be more than 24 characters.")])

    submit = SubmitField('Save Name')


    # ################################################
    def validate_group_name(self, group_name):
        result = re.fullmatch(r'([0-9A-Za-z- ~_.])+', group_name.data)
        if result is None:
            raise ValidationError(
                'Group name can only include, letters, numbers, spaces, and special characters: _ . ~ -')
