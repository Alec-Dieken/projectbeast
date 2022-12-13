from flask import current_app as app
from . import db, login_manager, bcrypt
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from sqlalchemy import or_, and_


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# ##########################################################################
# ############################# USER MODEL #################################
# ##########################################################################
class Users(db.Model, UserMixin):
    '''Table to store all user information.'''

    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(24), unique=True)
    firstname = db.Column(db.String(24), nullable=False)
    lastname = db.Column(db.String(24))
    user_picture_url = db.Column(
        db.Text, default=f'/static/images/global/default1.svg')
    bio = db.Column(db.Text)
    user_created_on = db.Column(db.DateTime, default=db.func.now())
    is_validated = db.Column(db.Boolean, default=False)

    nightmode = db.Column(db.Boolean, default=True)
    is_demo_account = db.Column(db.Boolean, nullable=False, default=False)

    is_fb_account = db.Column(db.Boolean, default=False)
    fb_id = db.Column(db.Text, unique=True)

    is_tw_account = db.Column(db.Boolean, default=False)
    tw_id = db.Column(db.Text, unique=True)

    is_google_account = db.Column(db.Boolean, default=False)
    g_id = db.Column(db.Text, unique=True)

    is_github_account = db.Column(db.Boolean, default=False)
    git_id = db.Column(db.Text, unique=True)


    # ########################## RELATIONSHIPS #################################
    # ##########################################################################
    tasks = db.relationship('Tasks', secondary='user_tasks', backref='users')
    projects = db.relationship(
        'Projects', secondary='user_projects', backref='users')
    groups = db.relationship(
        'Groups', secondary='user_groups', backref='users')

    req_recs = db.relationship('RequestReceivers', backref='users')


    # ############################ CLASS METHODS ###############################
    # ##########################################################################
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')


    # ##########################################################################
    def get_account_validation_token(self, expires_sec=604800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')


    # ##########################################################################
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])

        user_id = s.loads(token)['user_id']

        return Users.query.get(user_id)


    # ##########################################################################
    def is_social_account(self):
        if self.is_fb_account or self.is_tw_account or self.is_google_account or self.is_github_account:
            return True
        else:
            return False


    # ##########################################################################
    def get_peers(self):
        peers = Peers.query.filter(
            or_(Peers.user_id == self.id, Peers.user_id2 == self.id)).all()
        peer_users_info = []
        for peer in peers:
            peer_users_info.append(peer.get_peer(self.id))

        return peer_users_info

    
    # ##########################################################################
    def get_active_requests(self):
        active_requests = []
        for request in self.req_recs:
            item = Requests.query.filter(
                and_(Requests.id == request.request_id, Requests.is_active == True)).first()
            if not item is None:
                active_requests.append(item)
        return active_requests

    
    # ##########################################################################
    def get_active_projects(self, group_id=None):
        if group_id is None:
            projects = [
                project for project in self.projects if project.is_active]
            active_projects = []
            for project in projects:

                group = Groups.query.get(project.group_id)
                user_group = UserGroups.query.filter(
                    and_(UserGroups.user_id == self.id, UserGroups.group_id == group.id)).first()
                tasks = [task for task in self.tasks if task.project_id ==
                         project.id and task.is_active]
                active_projects.append({'id': project.id, 'name': project.project_name, "description": project.description,
                                        'group': group, 'role': user_group.role, 'user_added_on': user_group.user_added_on,
                                        'tasks': tasks, 'num_of_tasks': len(tasks)})

            return active_projects

        else:
            projects = self.projects
            active_projects = []
            for project in projects:
                if project.is_active and project.group_id == group_id:
                    group = Groups.query.get(project.group_id)
                    user_group = UserGroups.query.filter(
                        and_(UserGroups.user_id == self.id, UserGroups.group_id == group.id)).first()
                    tasks = [task for task in self.tasks if task.project_id ==
                             project.id and task.is_active]
                    active_projects.append({'id': project.id, 'name': project.project_name, "description": project.description,
                                            'group': group, 'role': user_group.role, 'user_added_on': user_group.user_added_on,
                                            'tasks': tasks, 'num_of_tasks': len(tasks)})

            return active_projects

    
    # ##########################################################################
    def get_active_tasks(self, group_id=None):
        if group_id is None:
            tasks = [task for task in self.tasks if task.is_active]
            active_tasks = []
            for task in tasks:
                project = Projects.query.get(task.project_id)
                group = Groups.query.get(project.group_id)

                active_tasks.append({'id': task.id, 'name': task.task_name, 'priority': task.priority, 'type': task.type, 'description': task.description,
                                    'project': project, 'group': group, 'group_name': group.group_name, 'task_created_on': task.task_created_on})

            return active_tasks

        else:
            tasks = [task for task in self.tasks if task.is_active]
            active_tasks = []
            for task in tasks:
                project = Projects.query.get(task.project_id)
                if project.group_id == group_id:
                    group = Groups.query.get(project.group_id)

                    active_tasks.append({'id': task.id, 'name': task.task_name, 'priority': task.priority, 'type': task.type, 'description': task.description,
                                        'project': project, 'group': group, 'group_name': group.group_name, 'task_created_on': task.task_created_on})

            return active_tasks


    # ##########################################################################
    def get_recent_activity(self):
        return RecentActivity.query.filter_by(user_id=self.id).order_by(RecentActivity.created_at.desc()).limit(10).all()


    # ##########################################################################
    def is_in_group(self, group_id):
        if UserGroups.query.filter(and_(UserGroups.group_id == group_id, UserGroups.user_id == self.id)).first():
            return True
        else:
            return False


    # ##########################################################################
    def request_exists(self, type, sender):
        requests = RequestReceivers.query.filter(
            RequestReceivers.receiver_id == self.id).all()
        for request in requests:
            exists = Requests.query.filter(and_(Requests.id == request.request_id, Requests.type ==
                                           type, Requests.sender_id == sender, Requests.is_active == True)).first()
            if exists:
                return True
        return False


    # ##########################################################################
    @classmethod
    def register(cls, email, password, username, firstname, lastname, is_validated=False):
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        return cls(email=email, password=password_hash,
                   username=username, firstname=firstname, lastname=lastname, is_validated=is_validated)


    # ##########################################################################
    @classmethod
    def authenticate(cls, email, password):
        user = Users.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return False


# ##########################################################################
# ######################### USER-PROJECTS MODEL ############################
# ##########################################################################
class UserProjects(db.Model):
    '''Relationship table for users & projects'''

    __tablename__ = 'user_projects'

    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id'), primary_key=True)
    proj_id = db.Column(db.Integer, db.ForeignKey(
        'projects.id'), primary_key=True)


# ##########################################################################
# ########################### PROJECTS MODEL ###############################
# ##########################################################################
class Projects(db.Model):
    '''Table to store all project information'''

    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
    project_created_on = db.Column(db.DateTime, default=db.func.now())
    num_of_tasks = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)


# ##########################################################################
# ########################## USER-GROUPS MODEL #############################
# ##########################################################################
class UserGroups(db.Model):
    '''Relationship table for users & groups'''

    __tablename__ = 'user_groups'

    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey(
        'groups.id'), primary_key=True)
    role = db.Column(db.Text, nullable=False, default='Contributor')
    user_added_on = db.Column(db.DateTime, default=db.func.now())


# ##########################################################################
# ############################# GROUPS MODEL ###############################
# ##########################################################################
class Groups(db.Model):
    '''Table to store all group information'''

    __tablename__ = 'groups'

    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(24), nullable=False)
    group_link = db.Column(db.Text, nullable=False, unique=True)
    group_created_on = db.Column(db.DateTime, default=db.func.now())
    group_image = db.Column(
        db.Text, default='/static/images/groups/default/robot1.svg')


    # ##########################################################################
    @classmethod
    def group_exists(cls, name):
        return True if Groups.query.filter_by(group_name=name).first() else False


    # ##########################################################################
    def get_users(self):
        user_groups = UserGroups.query.filter(
            UserGroups.group_id == self.id).all()
        return [Users.query.get(user.user_id) for user in user_groups]


# ##########################################################################
# ########################### USER-TASKS MODEL #############################
# ##########################################################################
class UserTasks(db.Model):
    '''Relationship table for users & groups'''

    __tablename__ = 'user_tasks'

    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id'), primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey(
        'tasks.id'), primary_key=True)
    user_added_on = db.Column(db.DateTime, default=db.func.now())


# ##########################################################################
# ############################# TASKS MODEL ################################
# ##########################################################################
class Tasks(db.Model):
    '''Table to store all group information'''

    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(50), nullable=False)
    type = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(9), nullable=False, default='low')
    description = db.Column(db.Text)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
    task_created_on = db.Column(db.DateTime, default=db.func.now())
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    task_completed_on = db.Column(db.DateTime)


# ##########################################################################
# ############################# PEERS MODEL ################################
# ##########################################################################
class Peers(db.Model):
    '''Table of connections between users'''
    __tablename__ = 'peers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_id2 = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


    # ##########################################################################
    @classmethod
    def link_users(cls, user1, user2):
        link = Peers.query.filter(or_(and_(Peers.user_id == user1.id, Peers.user_id2 == user2.id),
                                      and_(Peers.user_id == user2.id, Peers.user_id2 == user1.id))).first()

        if link:
            return None
        else:
            return cls(user_id=user1.id, user_id2=user2.id)


    # ##########################################################################
    @classmethod
    def are_peers(cls, id1, id2):
        peer = Peers.query.filter(or_(and_(Peers.user_id == id1, Peers.user_id2 == id2),
                                      and_(Peers.user_id == id2, Peers.user_id2 == id1))).first()

        if peer:
            return peer
        else:
            return None


    # ##########################################################################
    def get_peer(self, current_user_id):
        if self.user_id == current_user_id:
            user = Users.query.get(self.user_id2)
        else:
            user = Users.query.get(self.user_id)

        return user


# ##########################################################################
# ########################### REQUESTS MODEL ###############################
# ##########################################################################
class Requests(db.Model):
    __tablename__ = 'requests'

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Text, nullable=False)
    message = db.Column(db.Text, nullable=False)
    sender_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_username = db.Column(db.String(24), nullable=False)
    action_url = db.Column(db.Text, nullable=False, default='/')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    result = db.Column(db.String(8))
    request_sent_on = db.Column(db.DateTime, default=db.func.now())


# ##########################################################################
# ###################### REQUESTS RECEIVERS MODEL ##########################
# ##########################################################################
class RequestReceivers(db.Model):
    __tablename__ = 'request_receivers'

    request_id = db.Column(db.Integer, db.ForeignKey(
        'requests.id'), primary_key=True)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False)


# ##########################################################################
# ######################## RECENT ACTIVITY MODEL ###########################
# ##########################################################################
class RecentActivity(db.Model):
    __tablename__ = 'recent_activity'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    type = db.Column(db.Text, nullable=False)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())


# ##########################################################################
# ########################### MESSAGES MODEL ###############################
# ##########################################################################
class Messages(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    room_name = db.Column(db.Integer, db.ForeignKey('peers.id'))
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    sent_at = db.Column(db.DateTime, default=db.func.now())
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    
    
    # ##########################################################################
    peers = db.relationship('Peers', backref='messages')


    # ##########################################################################
    @classmethod
    def get_room_names(cls, id):
        room_names = set()
        room_names_query = Messages.query.with_entities(Messages.room_name).filter(
            or_(Messages.sender_id == id, Messages.receiver_id == id)).all()

        for room_name in room_names_query:
            room_names.add(room_name.room_name)

        return room_names


    # ##########################################################################
    @classmethod
    def get_message_link_info(cls, room_names, user_id):
        message_link_info = []
        for room_name in room_names:
            last_message = Messages.query.filter(
                Messages.room_name == room_name).order_by(Messages.sent_at.desc()).first()
            peer = Peers.query.get(room_name).get_peer(user_id)
            sender_text = 'You' if last_message.sender_id == user_id else peer.username
            sent_at = last_message.sent_at.time().strftime('%I:%M %p')
            is_read = True if (last_message.is_read) or (
                last_message.sender_id == user_id) else False
            message_link_info.append({'message': last_message.message, 'sender_text': sender_text, 'sent_at': sent_at,
                                      'room_name': room_name, 'peer_username': peer.username, 'peer_photo': peer.user_picture_url,
                                      'is_read': is_read})

        return message_link_info
