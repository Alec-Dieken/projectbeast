import random
from projectbeast.models import *

def generate_username(username):
    if Users.query.filter_by(username=username).first():
        return generate_username(username + str(random.randint(0, 9)))
    return username

def generate_group_link(group_name, tag=1):
    if tag <= 1:
        new_group_link = group_name.lower().replace(' ', '_')
    else:
        new_group_link = group_name.lower().replace(' ', '_') + '_' + str(tag)
    if Groups.query.filter_by(group_link=new_group_link).first():
        return generate_group_link(group_name, tag + 1)
    return new_group_link
