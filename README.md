CONTENTS OF THIS FILE
---------------------

 * Introduction
 * How to Use
 * Maintainers
 
 
INTRODUCTION
------------

projectbeast.io is a flask-based project management website designed to help its users collaborate and manage project-related tasks. It utilizes a hierarchy of different user roles, each with their own distinct functionality, organized into 'groups', where group specific projects and tasks are created and managed. Users are also able to become 'peers' with each other, which gives them the ability to invite each other to their groups and participate in the live instant messaging feature. Data is stored in a PostgreSQL database and the web sockets used to handle the chat feature are created and managed using socket.io.

HOW TO USE
----------

Create an account by registering with a personal email, or by using one of the social media login buttons. If registering with a personal email, you will receive a link in your email that will validate your account before you can login.

Once logged in, you can immediately create groups, look up other users and send them peer invites, or edit your account.
To edit your profile image, click on the image on your account page, which will show a file upload form. Choose the image you want to upload (must be .png, .jpg, or .jpeg) and click upload image. Image data is uploaded, cropped (using content detection AI), and resized by Tinify's free API account (https://tinypng.com/developers)

Groups are located on the far-right navigation menu. Here you can create a new group by click on the + icon, or click on an existing group icon to view it's contents. Groups will contain all your projects, tasks, and memebers, who are orginized by superiority ( creator > admin > member ).

MAINTAINERS
-----------

Current maintainers:
 * Alec Dieken (Alec-Dieken) - https://github.com/Alec-Dieken
