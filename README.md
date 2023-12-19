CONTENTS OF THIS FILE
---------------------

 * Introduction
 * Technologies Used
 * Website Navigation
 * Upcoming Features/Bug Fixes
 * Maintainers
 
 
INTRODUCTION
------------

**ProjectBeast** (https://projectbeast.online) is a flask-based project management website designed to help its users collaborate and manage project-related tasks. It utilizes a hierarchy of different user roles, each with their own distinct functionality, organized into 'groups', where group specific projects and tasks are created and managed.

Users are also able to become 'peers' with each other, which gives them the ability to invite each other to their groups and participate in the live instant messaging feature. Data is stored in a PostgreSQL database and the web sockets used to handle the chat feature are created and managed using Flask-SocketIO.

TECHNOLOGIES USED
------------

**Frontend**: Javascript, Jinja2, Socket.IO<br/>
**Backend**: Flask, Python, Flask-SocketIO<br/>
**Database**: PostgreSQL<br/>
**Deployment**: NGINX, Gunicorn, Eventlet

WEBSITE NAVIGATION
----------

**Create an account** by registering with a personal email, or by using one of the social media login buttons. If registering with a personal email, you will receive a link in your email that will validate your account before you can login. You can also browse the website by clicking the the demo account link on the login or registration pages, which will allow you navigate the site freely, minus the ability to make changes to the account.

Once logged in, you can immediately create groups, look up other users, send out peer invites, or edit your account.
To edit your profile image, click on the image on your account page, which will show a file upload form. Choose the image you want to upload (must be .png, .jpg, or .jpeg) and click upload image. Image data is uploaded, cropped (using content detection AI), and resized by Tinify's free API (https://tinypng.com/developers)

Groups are located on the far-right navigation menu. Here you can create a new group by clicking on the + icon, or you can click on an existing group icon to view it's contents. Groups will contain all the group-related projects, tasks, and memebers - orginized by superiority ( creator > admin > member ). Each rank will have different levels of control to edit the group and projects.

To use the live instant messaging feature, you must be 'peers' with that other person. You can become peers with someone by looking them up by username and clicking on the 'add peer' button, or if they are in the same group as you, you can add them from the member list. Once they accept, you can then navigate to the peers page from the link on the left-side menu, then click on message.

UPCOMING FEATURES/BUG FIXES
-----------
* Currently, the pages for 'privacy policy', 'terms and conditions', and 'how-to-delete-your-account' pages are blank, which are required for using the social media APIs. These pages are on their way. This website is simply for demonstration purposes, and if you wish to delete your account, you may go to your account page and click on 'delete account' or you can send me an email to alec@alecdieken.com
* Pages with long group/project/task names cause bad styling at the top of the page. This will be fixed soon.
* There is currently very little responsive UI for the website once logged-in. A mobile-friendly version is in the works.

MAINTAINERS
-----------

Current maintainers:
 * Alec Dieken (Alec-Dieken) - https://github.com/Alec-Dieken