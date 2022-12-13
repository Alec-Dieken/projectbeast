import os, secrets, random, tinify

from flask import render_template, redirect, flash, url_for, request, session
from flask import current_app as app

from . import socketio, bcrypt, oauth

from projectbeast.forms import (SignupForm, LoginForm, RequestResetForm,
    ResetPasswordForm, AddProjectForm, AddTaskForm, AddGroupForm, AddProjectFormNoGroup,
    AddGroupMemberForm, EditAccountForm, UploadImage, EditGroupForm, AddTaskFormNoProject)

from projectbeast.models import (db, Users, Projects, UserProjects, Tasks,
    UserTasks, Groups, UserGroups, Peers, Requests, RecentActivity, RequestReceivers, Messages)

from projectbeast.generate_names import generate_username, generate_group_link
from projectbeast.generate_emails import send_pw_reset_email, send_validation_email

from sqlalchemy import or_, and_, func

from flask_login import login_user, current_user, logout_user, login_required

import requests_oauthlib
from requests_oauthlib.compliance_fixes import facebook_compliance_fix

from flask_socketio import send, join_room

from werkzeug.utils import secure_filename


# ##################################################################################################################
# ############################################# GLOBAL VARIABLES ###################################################
# ##################################################################################################################
# Web App Base URL
URL = "https://projectbeast.io"

# IMPORTANT FACEBOOK DECLARATIONS
# In Facebook Developer dashboard, Valid OAuth Redirect URIs should be: {URL}/facebook/auth
FB_CLIENT_ID = os.environ.get('FB_CLIENT_ID')
FB_CLIENT_SECRET = os.environ.get('FB_CLIENT_SECRET')
FB_AUTHORIZATION_BASE_URL = "https://www.facebook.com/dialog/oauth"
FB_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"
FB_SCOPE = ["email"]

# IMPORTANT TWITTER DECLARATIONS
# In Twitter Developer dashboard, Callback URI / Redirect URL should be: {URL}/twitter/auth
TWITTER_CLIENT_ID = os.environ.get('TWITTER_CLIENT_ID')
TWITTER_CLIENT_SECRET = os.environ.get('TWITTER_CLIENT_SECRET')
TWITTER_API_BASE = 'https://api.twitter.com/1.1/'

# IMPORTANT GOOGLE DECLARATIONS
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_CONFIG_URL = "https://accounts.google.com/.well-known/openid-configuration"

# IMPORTANT GITHUB DECLARATIONS
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_BASE_URL = "https://api.github.com"
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"

# TINIFY VARIABLES
tinify.key = os.environ.get('TINIFY_KEY')

# Allows http callback
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# ##################################################################################################################
# ######################################### EMAIL/PASSWORD USER ROUTES #############################################
# ##################################################################################################################
@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Route for main registration page'''

    # if user is already logged in, send them to dashboard page
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # initialize signup form
    form = SignupForm()
    
    # if request is post, form is submitted, and fields are validated...
    if form.validate_on_submit():
        # gather form data
        email = form.email.data
        password = form.password.data
        username = form.username.data
        firstname = form.firstname.data
        lastname = form.lastname.data

        # register new user with Users.register method (but don't validate account yet)
        user = Users.register(email=email, password=password, username=username,
                              firstname=firstname, lastname=lastname)

        # add new user to db
        db.session.add(user)
        db.session.commit()
        
        # send an email to new user with a generated token that will validate their account when visited
        send_validation_email(user)
        
        # send back to login page
        flash('Please check your email to validate your account.', 'info')
        return redirect(url_for('login'))
    else:
        # GET request
        return render_template('/auth/register.html', form=form, pb_title='Sign up!')


# ###################################### REGISTER VALIDATION ######################################################
@app.route('/register/validate/<token>')
def validate_email(token):
    '''Route for validating account tokens sent through email.'''
    
    # if the current user is already logged in - send them to the dashboard page
    if current_user.is_authenticated:
        flash('You have already validated your account.')
        return redirect(url_for('dashboard'))

    # verify that the token in the link matches the one for their account
    user = Users.verify_reset_token(token)

    # if token doesn't match or is expired - redirect back to login page
    if user is None:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('login'))

    #  else validate their account, log them in, and send them to dashboard
    user.is_validated = True
    db.session.commit()
    login_user(user)
    flash('Congrats! Your account has been validated!', 'success')
    return redirect(url_for('dashboard'))


# ############################################# LOGIN ##############################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Route for main login page'''
    
    # if current user is logged in and their account is validated - send them to dashboard page
    if current_user.is_authenticated and current_user.is_validated:
        return redirect(url_for('dashboard'))

    # initialize login form
    form = LoginForm()
    # if request is post, form is submitted, and fields are validated...
    if form.validate_on_submit():
        # check that their email and password are a match
        user = Users.authenticate(form.email.data, form.password.data)
        # if they are a match...
        if user:
            # but not validated - flash message and refresh page
            if not user.is_validated:
                flash('Please check your email for validation link before logging in.')
                return redirect(url_for('login'))

            # to prevent users from signing in with email and password if they have a social media account
            if user.is_social_account():
                flash('Please login using the social media account you registered with.', 'error')
                return redirect(url_for('login'))
            
            # sign in user and send them to dashboard page
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        
        # if email and password are not a match - flash message and refresh page
        else:
            flash('Email and/or password are incorrect.', 'error')
            return redirect(url_for('login'))

    return render_template('/auth/login.html', form=form, pb_title='Login')


# ############################################ LOGOUT ##############################################################
@app.route('/logout')
def logout():
    '''Route for handling user logout'''
    
    logout_user()
    return redirect(url_for('login'))


# ############################################ RESET PASSWORD ######################################################
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    '''Route for getting user email to send validation link to if they forgot their password'''
    
    # if the user is already logged in - send them to dashboard page
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # initialize password reset request form
    form = RequestResetForm()
    # if request is post, form is submitted, and fields are validated...
    if form.validate_on_submit():
        # look up user by their email
        user = Users.query.filter_by(email=form.email.data).first()
        
        # if user doesn't exist - flash message and redirect back to login page
        if user is None:
            flash('If that address is associated with an account, please check your email for further instructions.', 'info')
            return redirect(url_for('login'))

        # if the account is a social media account - flash message and redirect back to login page
        if user.is_social_account():
            flash('Cannot change password for a social media account.', 'error')
            return redirect(url_for('login'))

        # else send email, flash message, and redirect back to login page
        send_pw_reset_email(user)
        flash('If that address is associated with an account, please check your email for further instructions.', 'info')
        return redirect(url_for('login'))
    
    # GET request
    return render_template('/auth/reset-password.html', pb_title='Reset Password', form=form)


# ##################################################################################################################
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    user = Users.verify_reset_token(token)
    
    if user is None:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('reset_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        password_hash = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user.password = password_hash
        db.session.commit()
        flash('Your password has been successfully changed.', 'success')
        return redirect(url_for('login'))
    
    return render_template('/auth/reset-token.html', pb_title='Reset Password', form=form)


# ##################################################################################################################
@app.route('/privacy-policy')
def privacy_policy():
    '''Route for viewing privacy-policy... SOON TO COME'''
    return '<h2>Privacy Policy</h2>'


# ##################################################################################################################
@app.route('/how-to-delete')
def how_to_delete():
    '''Route for viewing account deletion instruction required by Facebook... SOON TO COME'''
    return '<h2>How to Delete Your Account</h2>'


# ##################################################################################################################
@app.route('/terms-and-conditions')
def terms_and_conditions():
    '''Route for viewing terms and conditions... SOON TO COME'''
    return '<h2>Terms and Conditions</h2>'


# ##################################################################################################################
# ############################################## FACEBOOK ROUTES ###################################################
# ##################################################################################################################
@app.route("/facebook")
def facebook_login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    facebook = requests_oauthlib.OAuth2Session(
            FB_CLIENT_ID, redirect_uri=URL + "/facebook/auth", scope=FB_SCOPE)
    authorization_url, _ = facebook.authorization_url(
            FB_AUTHORIZATION_BASE_URL)

    return redirect(authorization_url)

# ##################################################################################################################
@app.route("/facebook/auth")
def facebook_auth():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    try:
        facebook = requests_oauthlib.OAuth2Session(
            FB_CLIENT_ID, scope=FB_SCOPE, redirect_uri=URL + "/facebook/auth")
        facebook = facebook_compliance_fix(facebook)
        facebook.fetch_token(
            FB_TOKEN_URL, client_secret=FB_CLIENT_SECRET, authorization_response=request.url)

        user_data = facebook.get(
            "https://graph.facebook.com/me?fields=first_name,last_name,email,picture.width(256).height(256){url}").json()

        fb_id = user_data.get('id')
        firstname = user_data.get('first_name')
        lastname = user_data.get('last_name')
        email = user_data.get('email')
        profile_pic = user_data.get("picture").get("data").get("url")

        check_user = Users.query.filter_by(fb_id=fb_id).first()
        if check_user:
            login_user(check_user)
            return redirect(url_for('dashboard'))

        else:
            if Users.query.filter_by(email=email).first():
                flash('An account with that email already exists', 'error')
                return redirect(url_for('login'))

            username = generate_username(firstname + lastname)
            password_hash = bcrypt.generate_password_hash(
                secrets.token_hex(24)).decode('utf-8')

            user = Users(is_fb_account=True, fb_id=fb_id, username=username, email=email,
                         firstname=firstname, lastname=lastname, password=password_hash,
                         user_picture_url=profile_pic, is_validated=True)

            db.session.add(user)
            db.session.commit()
            login_user(user)

            return redirect(url_for('dashboard'))

    except:
        flash('There was a problem validating your Facebook account.', 'error')
        return redirect(url_for('register'))


# ##################################################################################################################
# ############################################## TWITTER ROUTES ####################################################
# ##################################################################################################################
@app.route('/twitter')
def twitter_login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    oauth.register(
            name='twitter',
            client_id=TWITTER_CLIENT_ID,
            client_secret=TWITTER_CLIENT_SECRET,
            request_token_url='https://api.twitter.com/oauth/request_token',
            request_token_params=None,
            access_token_url='https://api.twitter.com/oauth/access_token',
            access_token_params=None,
            authorize_url='https://api.twitter.com/oauth/authenticate',
            authorize_params=None,
            api_base_url=TWITTER_API_BASE,
            client_kwargs=None,
        )

    return oauth.twitter.authorize_redirect(f'{URL}/twitter/auth')



# ##################################################################################################################
@app.route('/twitter/auth')
def twitter_auth():
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    try:
        token = oauth.twitter.authorize_access_token()
        resp = oauth.twitter.get(
                f"{TWITTER_API_BASE}account/verify_credentials.json?include_email=true")
        user_data = resp.json()

        tw_id = str(user_data.get('id'))
        name = user_data.get('name')
        username = user_data.get('screen_name')
        email = user_data.get('email')
        profile_pic = f'/static/images/groups/default/robot{random.randint(1, 10)}.svg'

        check_user = Users.query.filter_by(tw_id=tw_id).first()

        if check_user:
            login_user(check_user)
            return redirect(url_for('dashboard'))

        else:
            if Users.query.filter_by(email=email).first():
                flash('An account with that email already exists', 'error')
                return redirect(url_for('login'))

            username = generate_username(username)
            password_hash = bcrypt.generate_password_hash(secrets.token_hex(24)).decode('utf-8')

            new_user = Users(is_tw_account=True, tw_id=tw_id, username=username, email=email,
                                firstname=name.split(' ')[0], lastname=' '.join(name.split(' ')[1:]),
                                password=password_hash, user_picture_url=profile_pic, is_validated=True)

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('dashboard'))
    except:
        flash('There was a problem validating your Twitter account.', 'error')
        return redirect(url_for('register'))


# ##################################################################################################################
# ############################################## GOOGLE ROUTES #####################################################
# ##################################################################################################################
@app.route('/google')
def google_login():

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=GOOGLE_CONFIG_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    return oauth.google.authorize_redirect(f'{URL}/google/auth')


# ##################################################################################################################
@app.route('/google/auth')
def google_auth():

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    try:
        token = oauth.google.authorize_access_token()
        user_data = token['userinfo']

        g_id = user_data.get('sub')
        firstname = user_data.get('given_name')
        lastname = user_data.get('family_name', '')
        email = user_data.get('email')
        profile_pic = user_data.get('picture', f'/static/images/groups/default/robot{random.randint(1, 10)}.svg')

        check_user = Users.query.filter_by(g_id=g_id).first()

        if check_user:
            login_user(check_user)
            return redirect(url_for('dashboard'))

        else:
            if Users.query.filter_by(email=email).first():
                flash('An account with that email already exists', 'error')
                return redirect(url_for('login'))

            username = generate_username(firstname + lastname)
            password_hash = bcrypt.generate_password_hash(
                secrets.token_hex(24)).decode('utf-8')

            new_user = Users(is_google_account=True, g_id=g_id, username=username, email=email,
                            firstname=firstname, lastname=lastname, password=password_hash,
                            user_picture_url=profile_pic, is_validated=True)

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('dashboard'))
    except:
        flash('There was a problem validating your Google account.', 'error')
        return redirect(url_for('register'))


# ##################################################################################################################
# ############################################## GITHUB ROUTES #####################################################
# ##################################################################################################################
@app.route('/github')
def github_login():

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    oauth.register(
        name='github',
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url=GITHUB_AUTH_URL,
        authorize_params=None,
        api_base_url=GITHUB_BASE_URL,
        client_kwargs={'scope': 'user:email'},
    )

    return oauth.github.authorize_redirect(f'{URL}/github/auth')


# ##################################################################################################################
@app.route('/github/auth')
def github_auth():

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    try:
        token = oauth.github.authorize_access_token()
        user_data = oauth.github.get('user', token=token).json()

        git_id = str(user_data.get('id'))
        username = user_data.get('login')
        email = user_data.get('email')
        name = user_data.get('name')
        profile_pic = user_data.get('avatar_url')

        check_user = Users.query.filter_by(git_id=git_id).first()

        if check_user:
            login_user(check_user)
            return redirect(url_for('dashboard'))

        else:
            if Users.query.filter_by(email=email).first():
                flash('An account with that email already exists', 'error')
                return redirect(url_for('login'))

            username = generate_username(username)
            password_hash = bcrypt.generate_password_hash(
                secrets.token_hex(16)).decode('utf-8')

            new_user = Users(is_github_account=True, git_id=git_id, username=username, email=email,
                            firstname=name.split(' ')[0], lastname=' '.join(name.split(' ')[1:]),
                            password=password_hash, user_picture_url=profile_pic, is_validated=True)

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('dashboard'))
    except:
        flash('There was a problem validating your Github account.', 'error')
        return redirect(url_for('register'))

# ##################################################################################################################
# ######################################## LOGIN REQUIRED ##########################################################
# ##################################################################################################################
@app.route('/')
@login_required
def dashboard():
    user = current_user

    # gathering import info
    requests = user.get_active_requests()
    peers = user.get_peers()
    active_projects = user.get_active_projects()
    active_tasks = user.get_active_tasks()
    recent_activity = user.get_recent_activity()
    session['previous_url'] = url_for('dashboard')

    # setting up form for creating a new project
    add_project_form = AddProjectForm()
    add_project_form.group_id.choices = [
        (group.id, group.group_name) for group in current_user.groups]

    # setting up form for creating a new task
    add_task_form = AddTaskForm()
    add_task_form.priority.choices = ['Low', 'Medium', 'High', 'Immediate']
    add_task_form.type.choices = ['Bug', 'Feature', 'Other']
    add_task_form.project_id.choices = [
        (project['id'], f"{project['name']} ({project['group'].group_name if project['group'] else 'none'})") for project in active_projects]

    # setting up form for creating a new group
    add_group_form = AddGroupForm()
    
    # gathering chart data
    low_priority = [task for task in active_tasks if task['priority']=='Low']
    med_priority = [task for task in active_tasks if task['priority']=='Medium']
    high_priority = [task for task in active_tasks if task['priority']=='High']
    imm_priority = [task for task in active_tasks if task['priority']=='Immediate']
    
    type_bug = [task for task in active_tasks if task['type']=='Bug']
    type_feature = [task for task in active_tasks if task['type']=='Feature']
    type_other = [task for task in active_tasks if task['type']=='Other']
    
    priority_is_empty = True if len(low_priority) + len(med_priority) + len(high_priority) + len(imm_priority) == 0 else False
    
    priority_chart_data = {'low': len(low_priority), 'med': len(med_priority), 'high': len(high_priority), 'imm': len(imm_priority)}
    type_chart_data = {'bug': len(type_bug), 'feature': len(type_feature), 'other': len(type_other)}
    
    type_is_empty = True if len(type_bug) + len(type_feature) + len(type_other) == 0 else False
    
    # render dashboard
    return render_template('/dashboard/dashboard.html', user=user, pb_title='Dashboard', active_projects=active_projects,
                           active_tasks=active_tasks, add_project_form=add_project_form, add_task_form=add_task_form,
                           add_group_form=add_group_form, requests=requests, peers=peers, recent_activity=recent_activity,
                           priority_chart_data=priority_chart_data, type_chart_data=type_chart_data, priority_is_empty=priority_is_empty,
                           type_is_empty=type_is_empty)


# ########################################## PROFILE PAGE ###########################################################
@app.route('/profile/<string:username>', methods=['GET', 'POST'])
@login_required
def account(username):
    profile_user = Users.query.filter(Users.username == username).first()
    user = current_user
    are_peers = Peers.are_peers(current_user.id, profile_user.id)

    if username != current_user.username and not are_peers:
        return redirect(session['previous_url'])

    form = EditAccountForm()
    image_form = UploadImage()
    
    session['previous_url'] = request.full_path

    if image_form.submit.data and image_form.validate_on_submit():

        filename = secure_filename(image_form.upload.data.filename)
        try:
            path = os.path.join(
                '/home/ajdieken/projectbeast/projectbeast/', 'static/images/users', filename)
            # image_form.upload.data.save(path)

            source = tinify.from_file(image_form.upload.data)
            resized = source.resize(method="cover", width=256, height=256)
            resized.to_file(path)
            user.user_picture_url = f"/static/images/users/{filename}"
            db.session.commit()
            return redirect(f'/profile/{user.username}')
        except:
            flash("There was a problem uploading your image.")
            return redirect('/')

    elif form.submit.data and form.validate_on_submit():
        current_user.firstname = form.firstname.data
        current_user.lastname = form.lastname.data
        current_user.username = form.username.data
        current_user.bio = form.bio.data

        db.session.commit()

        return redirect(url_for('account', username=form.username.data))

    else:
        return render_template('/dashboard/account.html', pb_title='Account', user=user, profile_user=profile_user, are_peers=are_peers,
                               form=form, image_form=image_form)


# ############################################ DELETE ACCOUNT ###########################################################
@app.route('/profile/<string:username>/delete', methods=['POST'])
@login_required
def delete_account(username):
    user = Users.query.filter(Users.username == username).first()
    
    if user is None or user.id != current_user.id:
        return redirect(url_for('dashboard'))
    
    else:
        user_tasks = UserTasks.query.filter(UserTasks.user_id == user.id).all()
        user_projects = UserProjects.query.filter(
            UserProjects.user_id == user.id).all()
        user_groups = UserGroups.query.filter(
            UserGroups.user_id == user.id).all()
        user_peers = Peers.query.filter(
            or_(Peers.user_id == user.id, Peers.user_id2 == user.id)).all()
        sent_requests = Requests.query.filter(
            Requests.sender_id == user.id).all()
        received_requests = RequestReceivers.query.filter(
            RequestReceivers.receiver_id == user.id).all()
        rec_act = RecentActivity.query.filter(
            RecentActivity.user_id == user.id).all()
        messages = Messages.query.filter(
            or_(Messages.sender_id == user.id, Messages.receiver_id == user.id)).all()

        for task in user_tasks:
            db.session.delete(task)
            db.session.commit()

        for project in user_projects:
            db.session.delete(project)
            db.session.commit()

        for group in user_groups:
            db.session.delete(group)
            db.session.commit()

        for peer in user_peers:
            db.session.delete(peer)
            db.session.commit()

        for request in sent_requests:
            req_rec = RequestReceivers.query.filter(
                RequestReceivers.request_id == request.id).all()
            for r in req_rec:
                db.session.delete(r)
                db.session.commit()
            db.session.delete(request)
            db.session.commit()

        for req in received_requests:
            db.session.delete(req)
            db.session.commit()

        for act in rec_act:
            db.session.delete(act)
            db.session.commit()

        for message in messages:
            db.session.delete(message)
            db.session.commit()

        logout()

        db.session.delete(user)
        db.session.commit()

        return redirect(url_for('register'))


# ############################################ SEARCH RESULTS #############################################################
@app.route('/search')
@login_required
def search_results():
    session['previous_url'] = request.full_path

    query = request.args.get('search')
    results = Users.query.filter(and_(Users.id != current_user.id, func.lower(
        Users.username).contains(query.lower()))).all()

    peers = current_user.get_peers()

    add_group_form = AddGroupForm()

    active_peer_requests = Requests.query.filter(and_(
        Requests.sender_id == current_user.id, Requests.type == 'add-peer', or_(Requests.is_active == True, 
                                                                                Requests.result == 'Declined'))).all()
    
    peer_request_ids = []
    for req in active_peer_requests:
        req_rec = RequestReceivers.query.filter(
            RequestReceivers.request_id == req.id).first()
        peer_request_ids.append(req_rec.receiver_id)

    return render_template('/dashboard/search.html', query=query, results=results, peers=peers, user=current_user, add_group_form=add_group_form, peer_request_ids=peer_request_ids)


# ############################################## PEER VIEW PAGE #########################################################
@app.route('/peers', methods=['GET', 'POST'])
@login_required
def peers_page():
    
    session['previous_url'] = request.full_path
    
    user = current_user
    peers = user.get_peers()
    add_group_form = AddGroupForm()

    return render_template('/dashboard/peers.html', user=user, peers=peers, add_group_form=add_group_form)


# ########################################## CREATE PEER INVITE #########################################################
@app.route('/peers/invite/<int:peer_id>', methods=['POST'])
@login_required
def peer_request(peer_id):
    peers_obj = Peers.are_peers(current_user.id, peer_id)
    if peers_obj:
        return redirect(session['previous_url'])

    current_user_requests = Requests.query.filter(and_(
        Requests.type == 'add-peer', Requests.sender_id == current_user.id, Requests.is_active == True)).all()
    
    for request in current_user_requests:
        if RequestReceivers.query.filter(and_(RequestReceivers.request_id == request.id, RequestReceivers.receiver_id == peer_id)).first():
            return redirect(session['previous_url'])

    new_request = Requests(sender_id=current_user.id, sender_username=current_user.username, type="add-peer",
                           message=f"{current_user.username} has requested to be peers.")
    db.session.add(new_request)
    db.session.flush()
    new_request.action_url = f'/peers/add/{new_request.id}'
    new_req_rec = RequestReceivers(
        request_id=new_request.id, receiver_id=peer_id)
    db.session.add(new_req_rec)
    db.session.commit()
    return redirect(session['previous_url'])


# ####################################### ACCEPT PEER INVITE ############################################################
@app.route('/peers/add/<int:req_id>', methods=['POST'])
@login_required
def add_peer(req_id):
    if not RequestReceivers.query.filter(and_(RequestReceivers.receiver_id == current_user.id, RequestReceivers.request_id == req_id)).first():
        return redirect(session['previous_url'])

    request = Requests.query.get(req_id)
    peer_id = request.sender_id
    peer = Users.query.get(peer_id)
    new_peer = Peers.link_users(peer, current_user)

    if new_peer:
        db.session.add(new_peer)

        request.is_active = False
        request.result = 'accepted'

        ra1 = RecentActivity(user_id=current_user.id, type='peers',
                             message=f'You and {peer.username} are now peers!')
        ra2 = RecentActivity(user_id=peer.id, type='peers',
                             message=f'You and {current_user.username} are now peers!')

        db.session.add(new_peer)
        db.session.add(ra1)
        db.session.add(ra2)
        db.session.commit()
        return redirect(session['previous_url'])
    else:
        flash('You are already peers with this user.')
        request.is_active = False
        db.session.commit()
        return redirect(session['previous_url'])


# ########################################## REMOVE PEER ##########################################################
@app.route('/peers/remove/<int:peer_id>', methods=['POST'])
@login_required
def remove_peer(peer_id):
    peer_obj = Peers.are_peers(current_user.id, peer_id)
    if peer_obj:
        db.session.delete(peer_obj)
        db.session.commit()
        messages = Messages.query.filter(or_(and_(Messages.sender_id == current_user.id, Messages.receiver_id == peer_id),
                                             and_(Messages.sender_id == peer_id, Messages.receiver_id == current_user.id))).all()

        for message in messages:
            db.session.delete(message)
        db.session.commit()

    return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/request/decline/<int:request_id>', methods=['POST'])
@login_required
def decline_request(request_id):
    request = Requests.query.filter(Requests.id == request_id).first()

    if request is None or request.is_active == False:
        return redirect(session['previous_url'])

    req_rec = RequestReceivers.query.filter(and_(
        RequestReceivers.receiver_id == current_user.id, RequestReceivers.request_id == request.id)).first()

    if req_rec is None:
        return redirect(session['previous_url'])

    request.is_active = False
    request.result = 'Declined'

    db.session.commit()
    return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/groups/add', methods=['POST'])
@login_required
def create_group():
    add_group_form = AddGroupForm()
    if add_group_form.validate_on_submit():
        group_name = add_group_form.group_name.data
        group_image = f'/static/images/groups/default/robot{random.randint(1, 10)}.svg'
        group_link = generate_group_link(group_name)

        new_group = Groups(group_name=group_name,
                           group_image=group_image, group_link=group_link)
        db.session.add(new_group)
        db.session.flush()
        group_ra = RecentActivity(user_id=current_user.id, type='new_group',
                                  message=f"Group '{new_group.group_name}' was successfully created at {new_group.group_created_on.time().strftime('%I:%M %p')}")
        db.session.add(group_ra)
        group_rel = UserGroups(user_id=current_user.id,
                               group_id=new_group.id, role='Creator')
        db.session.add(group_rel)
        db.session.commit()

        return redirect(f'/group/{new_group.group_link}')

    else:
        return redirect('/')


# ##################################################################################################################
@app.route('/group/<string:group_link>')
@login_required
def group_page(group_link):
    
    session['previous_url'] = request.path
    
    group = Groups.query.filter_by(group_link=group_link).first()
    if group is None or not current_user.is_in_group(group.id):
        return redirect('/')
    else:
        is_creator = True if UserGroups.query.filter(and_(
            UserGroups.group_id == group.id, UserGroups.user_id == current_user.id, UserGroups.role == 'Creator')).first() else False
        
        is_admin = True if UserGroups.query.filter(and_(UserGroups.group_id == group.id, UserGroups.user_id == current_user.id, or_(
            UserGroups.role == 'Admin', UserGroups.role == 'Creator'))).first() else False
        
        members = group.users
        
        if UserGroups.query.filter(and_(UserGroups.group_id == group.id, UserGroups.role == 'Creator')).first():
            group_creator = Users.query.get(UserGroups.query.filter(and_(UserGroups.group_id == group.id,
                                                                         UserGroups.role == 'Creator')).first().user_id)
        else:
            group_creator = None

        group_admins = [group_user for group_user in members if UserGroups.query.filter(and_(UserGroups.group_id == group.id,
                                                                                             UserGroups.user_id == group_user.id,
                                                                                             UserGroups.role == 'Admin')).first()]

        group_members = [group_user for group_user in members if UserGroups.query.filter(and_(UserGroups.group_id == group.id,
                                                                                              UserGroups.user_id == group_user.id,
                                                                                              UserGroups.role == 'Member')).first()]

        add_group_form = AddGroupForm()
        add_project_form = AddProjectFormNoGroup(group_id=group.id)

        add_task_form = AddTaskForm()
        add_task_form.priority.choices = ['Low', 'Medium', 'High', 'Immediate']
        add_task_form.type.choices = ['Bug', 'Feature', 'Other']
        project_choices = Projects.query.filter(
            and_(Projects.group_id == group.id, Projects.is_active == True)).all()
        add_task_form.project_id.choices = [
            (project.id, project.project_name) for project in project_choices]

        add_group_member_form = AddGroupMemberForm()
        peers = current_user.get_peers()
        add_group_member_form.peers.choices = [(user.id, user.username) for user in peers if not UserGroups.query.filter(
            and_(UserGroups.group_id == group.id, UserGroups.user_id == user.id)).first()]

        group_active_projects = current_user.get_active_projects(group.id)
        group_active_tasks = current_user.get_active_tasks(group.id)
        peer_ids = [peer.id for peer in current_user.get_peers()]
        
        return render_template('/dashboard/group.html', group=group, members=members,
                               add_group_form=add_group_form, add_project_form=add_project_form, add_task_form=add_task_form,
                               user=current_user, active_projects=group_active_projects, active_tasks=group_active_tasks, group_creator=group_creator, group_admins=group_admins, is_admin=is_admin,
                               add_group_member_form=add_group_member_form, group_members=group_members, peer_ids=peer_ids, is_creator=is_creator)


# ##################################################################################################################
@app.route('/group/<string:group_link>/edit', methods=['GET', 'POST'])
@login_required
def edit_group(group_link):

    group = Groups.query.filter(Groups.group_link == group_link).first()
    if group is None:
        return redirect(session['previous_url'])

    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()
    if user_group is None or user_group.role != 'Creator':
        return redirect(session['previous_url'])

    add_group_form = AddGroupForm()
    image_form = UploadImage()
    edit_group_form = EditGroupForm()
    session['previous_url'] = url_for('edit_group', group_link=group_link)

    if edit_group_form.validate_on_submit():
        new_group_name = edit_group_form.group_name.data
        new_group_link = generate_group_link(new_group_name)

        group.group_name = new_group_name
        group.group_link = new_group_link
        db.session.commit()

        return redirect(f'/group/{new_group_link}')

    elif image_form.validate_on_submit():
        try:
            filename = secure_filename(image_form.upload.data.filename)
            path = os.path.join('/home/ajdieken/projectbeast/projectbeast/',
                                'static/images/groups/custom', filename)

            source = tinify.from_file(image_form.upload.data)
            resized = source.resize(method="cover", width=256, height=256)
            resized.to_file(path)
            group.group_image = f"/static/images/groups/custom/{filename}"
            db.session.commit()
            return redirect(session['previous_url'])
        except:
            flash("Didn't work")
            return redirect('/')

    else:

        return render_template('/dashboard/edit-group.html', group=group, user=current_user, add_group_form=add_group_form, image_form=image_form, edit_group_form=edit_group_form)


# ##################################################################################################################
@app.route('/group/<string:group_link>/delete', methods=['POST'])
@login_required
def delete_group(group_link):

    group = Groups.query.filter(Groups.group_link == group_link).first()
    if group is None:
        return redirect(session['previous_url'])

    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()
    if user_group is None or user_group.role != 'Creator':
        return redirect(session['previous_url'])

    group_projects = Projects.query.filter(Projects.group_id == group.id).all()
    active_group_tasks = []
    all_group_tasks = []

    for project in group_projects:
        tasks = Tasks.query.filter(Tasks.project_id == project.id).all()
        if not tasks is None:
            for task in tasks:
                all_group_tasks.append(task)
        active_tasks = Tasks.query.filter(
            and_(Tasks.project_id == project.id, Tasks.is_active == True)).all()
        if not active_tasks is None:
            for task in active_tasks:
                active_group_tasks.append(task)

    if len(active_group_tasks) > 0:
        flash("Can't delete group with active tasks.")
        return redirect(session['previous_url'])
    else:
        group_users = UserGroups.query.filter(
            UserGroups.group_id == group.id).all()
        for task in all_group_tasks:
            user_tasks = UserTasks.query.filter(
                UserTasks.task_id == task.id).all()
            for user_task in user_tasks:
                db.session.delete(user_task)
            db.session.delete(task)
        db.session.commit()

        for project in group_projects:
            user_projects = UserProjects.query.filter(
                UserProjects.proj_id == project.id).all()
            for user_project in user_projects:
                db.session.delete(user_project)
            db.session.delete(project)
        db.session.commit()

        for group_user in group_users:
            db.session.delete(group_user)
        db.session.commit()

        db.session.delete(group)

        db.session.commit()

        return redirect('/')


# ##################################################################################################################
@app.route('/group/<string:group_link>/member/<int:member_id>/leave', methods=['POST'])
@login_required
def leave_group(group_link, member_id):
    if member_id != current_user.id:
        return redirect(session['previous_url'])

    group = Groups.query.filter(Groups.group_link == group_link).first()
    if group is None:
        return redirect(session['previous_url'])

    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()
    if user_group is None or user_group.role == 'Creator':
        return redirect(session['previous_url'])

    projects = Projects.query.filter(Projects.group_id == group.id).all()
    for project in projects:
        tasks = Tasks.query.filter(Tasks.project_id == project.id).all()
        for task in tasks:
            user_task = UserTasks.query.filter(
                and_(UserTasks.user_id == member_id, UserTasks.task_id == task.id)).first()
            db.session.delete(user_task)
        user_proj = UserProjects.query.filter(and_(
            UserProjects.user_id == member_id, UserProjects.proj_id == project.id)).first()
        db.session.delete(user_proj)

    db.session.delete(user_group)
    db.session.commit()

    return redirect('/')


# ##################################################################################################################
@app.route('/group/<string:group_link>/promote/<int:member_id>', methods=['POST'])
@login_required
def promote_group_member(group_link, member_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    member = Users.query.get(member_id)
    member_user_group = UserGroups.query.filter(
        and_(UserGroups.group_id == group.id, UserGroups.user_id == member.id)).first()
    my_user_group = UserGroups.query.filter(and_(
        UserGroups.group_id == group.id, UserGroups.user_id == current_user.id)).first()
    role = member_user_group.role

    if group is None or member is None or member_user_group is None or role == 'Admin' or role == 'Creator' or my_user_group is None or my_user_group.role == 'Member':
        return redirect(session['previous_url'])
    else:
        member_user_group.role = 'Admin'
        db.session.commit()
        return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/demote/<int:member_id>', methods=['POST'])
@login_required
def demote_group_member(group_link, member_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    member = Users.query.get(member_id)
    member_user_group = UserGroups.query.filter(
        and_(UserGroups.group_id == group.id, UserGroups.user_id == member.id)).first()
    my_user_group = UserGroups.query.filter(and_(
        UserGroups.group_id == group.id, UserGroups.user_id == current_user.id)).first()
    role = member_user_group.role

    if group is None or member is None or member_user_group is None or role == 'Member' or role == 'Creator' or my_user_group is None or my_user_group.role != 'Creator':
        return redirect(session['previous_url'])
    else:
        member_user_group.role = 'Member'
        db.session.commit()
        return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/remove/<int:member_id>', methods=['POST'])
@login_required
def remove_group_member(group_link, member_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    member = Users.query.get(member_id)
    member_user_group = UserGroups.query.filter(
        and_(UserGroups.group_id == group.id, UserGroups.user_id == member.id)).first()

    my_user_group = UserGroups.query.filter(and_(
        UserGroups.group_id == group.id, UserGroups.user_id == current_user.id)).first()
    role = member_user_group.role

    if group is None or member is None or member_user_group is None or my_user_group is None:
        return redirect(session['previous_url'])
    elif (my_user_group.role == 'Admin' and role == 'Member') or (my_user_group.role == 'Creator' and (role == 'Member' or role == 'Admin')):

        projects = Projects.query.filter(Projects.group_id == group.id).all()
        for project in projects:
            tasks = Tasks.query.filter(Tasks.project_id == project.id).all()
            for task in tasks:
                user_task = UserTasks.query.filter(
                    and_(UserTasks.user_id == member_id, UserTasks.task_id == task.id)).first()
                db.session.delete(user_task)
            user_proj = UserProjects.query.filter(and_(
                UserProjects.user_id == member_id, UserProjects.proj_id == project.id)).first()
            db.session.delete(user_proj)

        db.session.delete(member_user_group)
        db.session.commit()

        return redirect(session['previous_url'])
    else:
        return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/members/invite', methods=['POST'])
@login_required
def add_group_member(group_link):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    if group is None:
        return redirect(session['previous_url'])

    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()
    if user_group is None or user_group.role == 'Member':
        return redirect(session['previous_url'])

    add_group_member_form = AddGroupMemberForm()

    if add_group_member_form.validate_on_submit():
        users = add_group_member_form.peers.data
        for user_id in users:
            request_exists = Users.query.get(user_id).request_exists(
                'group-invite', current_user.id)
            if request_exists is False:
                new_request = Requests(type='group-invite',
                                       message=f"{current_user.username} has invited you to join their group '{group.group_name}'.",
                                       sender_id=current_user.id, sender_username=current_user.username)
                db.session.add(new_request)
                db.session.flush()
                new_request.action_url = f'/group/{group_link}/members/add/{new_request.id}'
                req_rec = RequestReceivers(
                    request_id=new_request.id, receiver_id=user_id)
                db.session.add(req_rec)
                db.session.commit()

        return redirect(session['previous_url'])
    else:
        return '<h2>failed</h2>'


# ##################################################################################################################
@app.route('/group/<string:group_link>/members/add/<int:req_id>', methods=['POST'])
@login_required
def join_group(group_link, req_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()

    request = Requests.query.filter(
        and_(Requests.id == req_id, Requests.is_active == True)).first()
    req_rec = RequestReceivers.query.filter(and_(RequestReceivers.request_id == req_id,
                                                 RequestReceivers.receiver_id == current_user.id)).first()

    user_group_exists = UserGroups.query.filter(and_(
        UserGroups.group_id == group.id, UserGroups.user_id == current_user.id)).first()

    if group is None or request is None or request.type != 'group-invite' or req_rec is None:
        return redirect(session['previous_url'])

    if user_group_exists:
        request.is_active = False
        db.session.commit()
        flash('You already belong to this group.')
        return redirect(session['previous_url'])

    request.is_active = False
    request.result = 'Accepted'
    user_group = UserGroups(user_id=current_user.id,
                            group_id=group.id, role='Member')
    db.session.add(user_group)
    ra1 = RecentActivity(user_id=current_user.id, type='joined-group',
                         message=f"You have successfully joined group '{group.group_name}'.")
    ra2 = RecentActivity(user_id=request.sender_id, type='joined-group',
                         message=f"{current_user.username} has successfully joined group '{group.group_name}'.")
    db.session.add(ra1)
    db.session.add(ra2)

    new_projects = Projects.query.filter(Projects.group_id == group.id).all()
    for project in new_projects:
        new_user_proj = UserProjects(
            user_id=current_user.id, proj_id=project.id)
        db.session.add(new_user_proj)
        new_tasks = Tasks.query.filter(Tasks.project_id == project.id)
        for task in new_tasks:
            new_user_task = UserTasks(user_id=current_user.id, task_id=task.id)
            db.session.add(new_user_task)
    db.session.commit()
    return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/projects/add', methods=['POST'])
@login_required
def create_project(group_link):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    if group is None:
        return redirect(session['previous_url'])

    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()
    if user_group is None or user_group.role == 'Member':
        return redirect(session['previous_url'])

    add_project_form = AddProjectForm()
    add_project_form.group_id.choices = [
        (group.id, group.group_name) for group in current_user.groups]

    if add_project_form.validate_on_submit():
        project_name = add_project_form.project_name.data
        project_description = add_project_form.description.data
        group_id = add_project_form.group_id.data

        new_project = Projects(project_name=project_name,
                               description=project_description, group_id=group_id)

        db.session.add(new_project)
        db.session.flush()
        group_users = UserGroups.query.filter(
            UserGroups.group_id == group_id).all()
        for user in group_users:
            new_user_project = UserProjects(
                user_id=user.user_id, proj_id=new_project.id)
            db.session.add(new_user_project)
        project_ra = RecentActivity(user_id=current_user.id, type='new_project',
                                    message=f"Project '{project_name}' was successfully created at {new_project.project_created_on.time().strftime('%I:%M %p')}")
        db.session.add(project_ra)
        db.session.commit()

        return redirect(session['previous_url'])
    else:
        return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/tasks/add', methods=['POST'])
@login_required
def create_task(group_link):

    group = Groups.query.filter(Groups.group_link == group_link).first()
    if group is None:
        return redirect(session['previous_url'])

    add_task_form = AddTaskForm()
    add_task_form.priority.choices = ['Low', 'Medium', 'High', 'Immediate']
    add_task_form.type.choices = ['Bug', 'Feature', 'Other']
    project_choices = Projects.query.filter(
        Projects.group_id == group.id).all()
    add_task_form.project_id.choices = [
        (project.id, project.project_name) for project in project_choices]

    if add_task_form.validate_on_submit():
        task_name = add_task_form.task_name.data
        task_description = add_task_form.description.data
        task_priority = add_task_form.priority.data
        task_type = add_task_form.type.data
        task_project_id = add_task_form.project_id.data

        new_task = Tasks(task_name=task_name, description=task_description,
                         priority=task_priority, type=task_type, project_id=task_project_id)
        db.session.add(new_task)
        db.session.flush()
        group_users = group.get_users()
        for user in group_users:
            task_rel = UserTasks(user_id=user.id, task_id=new_task.id)
            db.session.add(task_rel)
        db.session.commit()

        return redirect(session['previous_url'])

    else:
        return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/<int:project_id>')
@login_required
def project_view(group_link, project_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()

    if group is None or user_group is None:
        return redirect(session['previous_url'])

    project = Projects.query.filter(Projects.id == project_id).first()
    if project is None or project.group_id != group.id:
        return redirect(session['previous_url'])

    add_group_form = AddGroupForm()
    add_task_form = AddTaskFormNoProject(project_id=project_id)
    add_task_form.priority.choices = ['Low', 'Medium', 'High', 'Immediate']
    add_task_form.type.choices = ['Bug', 'Feature', 'Other']

    active_tasks = [task for task in current_user.get_active_tasks(
        group.id) if task['project'].id == project_id]

    return render_template('/dashboard/project.html', is_admin=True, user=current_user, group=group, project=project, add_task_form=add_task_form, add_group_form=add_group_form, active_tasks=active_tasks, active_projects=True)


# ##################################################################################################################
@app.route('/group/<string:group_link>/<int:project_id>/close', methods=['POST'])
@login_required
def close_project(group_link, project_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()

    if group is None or user_group is None or user_group.role == 'Member':
        return redirect(session['previous_url'])

    project = Projects.query.filter(Projects.id == project_id).first()
    if project is None or project.group_id != group.id:
        return redirect(session['previous_url'])

    active_project_tasks = Tasks.query.filter(
        and_(Tasks.project_id == project.id, Tasks.is_active == True)).all()

    if len(active_project_tasks):
        flash("Can't close a project with active tasks.")
        return redirect(f'/group/{group_link}/{project_id}')
    else:
        project.is_active = False
        db.session.commit()
        return redirect(f'/group/{group_link}')


# ##################################################################################################################
@app.route('/group/<string:group_link>/<int:project_id>/<int:task_id>')
@login_required
def view_task(group_link, project_id, task_id):

    group = Groups.query.filter(Groups.group_link == group_link).first()
    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()

    if group is None or user_group is None:
        return redirect(session['previous_url'])

    project = Projects.query.filter(Projects.id == project_id).first()
    if project is None or project.group_id != group.id:
        return redirect(session['previous_url'])

    task = Tasks.query.filter(Tasks.id == task_id).first()
    if task is None or task.project_id != project_id:
        return redirect(session['previous_url'])

    add_group_form = AddGroupForm()
    is_admin = True if UserGroups.query.filter(and_(UserGroups.group_id == group.id, UserGroups.user_id == current_user.id, or_(
        UserGroups.role == 'Admin', UserGroups.role == 'Creator'))).first() else False
    session['previous_url'] = url_for(
        'view_task', group_link=group_link, project_id=project_id, task_id=task_id)

    return render_template('/dashboard/task.html', user=current_user, group=group, project=project, task=task, add_group_form=add_group_form, is_admin=is_admin)


# ##################################################################################################################
@app.route('/group/<string:group_link>/<int:project_id>/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(group_link, project_id, task_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()

    if group is None or user_group is None or user_group.role == 'Member':
        return redirect(session['previous_url'])

    project = Projects.query.filter(Projects.id == project_id).first()
    if project is None or project.group_id != group.id:
        return redirect(session['previous_url'])

    task = Tasks.query.filter(Tasks.id == task_id).first()
    if task is None or task.project_id != project_id:
        return redirect(session['previous_url'])

    task.is_active = False
    task.task_completed_on = db.func.now()
    db.session.commit()

    return redirect(session['previous_url'])


# ##################################################################################################################
@app.route('/group/<string:group_link>/<int:project_id>/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(group_link, project_id, task_id):
    group = Groups.query.filter(Groups.group_link == group_link).first()
    user_group = UserGroups.query.filter(and_(
        UserGroups.user_id == current_user.id, UserGroups.group_id == group.id)).first()

    if group is None or user_group is None or user_group.role == 'Member':
        return redirect(session['previous_url'])

    project = Projects.query.filter(Projects.id == project_id).first()
    if project is None or project.group_id != group.id:
        return redirect(session['previous_url'])

    task = Tasks.query.filter(Tasks.id == task_id).first()
    if task is None or task.project_id != project_id:
        return redirect(session['previous_url'])

    db.session.delete(task)
    db.session.commit()

    return redirect(url_for('group_page', group_link=group_link))


# ##################################################################################################################
@app.route('/messages')
@login_required
def messages_home():
    rooms = Messages.get_room_names(current_user.id)
    info_for_message_link = Messages.get_message_link_info(
        rooms, current_user.id)

    return render_template('/dashboard/messages.html', info_for_message_link=info_for_message_link, user=current_user)


# ##################################################################################################################
@app.route('/messages/<string:peer_un>')
@login_required
def private_messaging(peer_un):
    peer = Users.query.filter_by(username=peer_un).first()
    if peer is None:
        return redirect('/')

    peer_obj = Peers.are_peers(current_user.id, peer.id)
    if not peer_obj:
        return redirect('/')

    session['previous_url'] = url_for('private_messaging', peer_un=peer_un)

    session['peer_username'] = peer_un

    add_group_form = AddGroupForm()
    messages = Messages.query.filter(Messages.room_name == peer_obj.id).order_by(
        Messages.sent_at.desc()).all()

    return render_template('/dashboard/message.html', messages=messages, user=current_user, peer=peer, add_group_form=add_group_form)


# ##################################################################################################################
# ########################################## SOCKETS ###############################################################
# ##################################################################################################################
@socketio.on('join')
def on_join(data):

    peer = Users.query.filter_by(username=session['peer_username']).first()

    if peer is None:
        return None

    peer_obj = Peers.are_peers(current_user.id, peer.id)
    if not peer_obj:
        return None

    room = peer_obj.id
    session['room'] = room

    join_room(room)


# ##################################################################################################################
@socketio.on('mark-as-read')
def mark_as_read():
    try:
        messages = Messages.query.filter(and_(
            Messages.room_name == session['room'],
            Messages.receiver_id == current_user.id,
            Messages.is_read == False)).all()

        for message in messages:
            message.is_read = True
            db.session.commit()
            
    except:
        return None


# ##################################################################################################################
@socketio.on('update-messages')
def update_message(data):
    message_data = data['message']
    peer = Peers.query.get(session['room']).get_peer(current_user.id)
    
    new_message = Messages(
        room_name=session['room'], sender_id=current_user.id, receiver_id=peer.id, message=message_data)
    
    db.session.add(new_message)
    db.session.flush()
    message_id = new_message.id
    db.session.commit()

    send({'message': message_data, 'sender': current_user.username,
          'message_id': message_id}, broadcast=True, room=session['room'])
