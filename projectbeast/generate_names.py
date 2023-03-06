import random
from projectbeast.models import *


### Define function to generate unique username ###
def generate_username(username):
    # Keep generating usernames until a unique one is found
    while Users.query.filter_by(username=username).first():
        # Append a random number to the input username
        username += str(random.randint(0, 9))
    return username



### Define function to generate unique group link ###
def generate_group_link(group_name, tag=1):
    # Generate initial group link
    new_group_link = group_name.lower().replace(' ', '_')
    if tag > 1:
        new_group_link += '_' + str(tag)

    # Check if initial group link already exists in database
    while Groups.query.filter_by(group_link=new_group_link).first():
        # If so, increment the tag and generate a new group link
        tag += 1
        new_group_link = group_name.lower().replace(' ', '_') + '_' + str(tag)

    # Return the unique group link
    return new_group_link

