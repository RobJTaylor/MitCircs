#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2, logging, os
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
import flask_cors
from google.appengine.ext import ndb, blobstore, webapp
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.blobstore import BlobKey
import google.auth
import google.auth.transport.requests
import google.oauth2.id_token
import requests_toolbelt.adapters.appengine
from werkzeug.utils import secure_filename
from werkzeug.http import parse_options_header
from google.appengine.api import mail
import uuid

ALLOWED_EXTENSIONS = set (['doc', 'docx', 'pdf', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mitcircs_super_secret_key'

requests_toolbelt.adapters.appengine.monkeypatch()
HTTP_REQUEST = google.auth.transport.requests.Request()

class User(ndb.Model):
    id = ndb.StringProperty()
    name = ndb.StringProperty()
    account = ndb.StringProperty()

class Request(ndb.Model):
    email = ndb.StringProperty()
    name = ndb.StringProperty()
    reason = ndb.StringProperty()
    instructor = ndb.StringProperty()
    description = ndb.StringProperty()
    file_key = ndb.BlobKeyProperty()
    status = ndb.StringProperty()
    uuid = ndb.StringProperty()

class SupportingDocument(ndb.Model):
    user = ndb.StringProperty()
    blob_key = ndb.BlobKeyProperty()

class InstructorCode(ndb.Model):
    user_id = ndb.StringProperty()
    uuid = ndb.StringProperty()

class AdminCode(ndb.Model):
    user_id = ndb.StringProperty()
    uuid = ndb.StringProperty()

@app.route('/', methods=['GET', 'POST'])
def index():
    session['userId'] = None
    session['username'] = None

    if session.get('error'):
        session['error'] = None
        return render_template('index.html', error=session['error'])

    #Check for auth token from ajax call (firebase)
    if 'Authorization' in request.headers:
        id_token = request.headers['Authorization'].split(' ').pop()
        email = request.headers['Email'].split(' ').pop()
        name = request.headers['Username'].split(' ').pop()
        session['userId'] = email
        session['username'] = name
        claims = google.oauth2.id_token.verify_firebase_token(id_token, HTTP_REQUEST)
        if claims:
            user_id = registerUser(email, name)
            return 'authorized'
        else:
            return 'Not authorized', 401     
    else:
        return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    requestQuery = Request.query(Request.email == session['userId'])
    userQuery = User.query(User.id == session['userId'])

    for user in userQuery:
        session['account'] = user.account

    if session['userId'] == None:
        session['error'] = 1
        return redirect(url_for('index'))

    if session.get('success'):
        success = session['success']
        session['success'] = None
        return render_template('dashboard.html', user=session['userId'], name=session['username'], success=success)
    elif session.get('failure'):
        failure = session['failure']
        session['failure'] = None
        return render_template('dashboard.html', user=session['userId'], name=session['username'], failure=failure)

    return render_template('dashboard.html', user=session['userId'], name=session['username'], requests=requestQuery, account = session['account'])

@app.route('/submit_request', methods=['GET', 'POST'])
def submit_request():
    submitHandler = blobstore.create_upload_url('/submit_handler', gs_bucket_name="mitcircs")
    query = User.query(User.account == "instructor")
    for instructor in query:
        if instructor.id == "":
            return render_template('submit_request.html', user=session['userId'], name=session['username'], submitHandler=submitHandler, instructors = None, account = session['account'])

    return render_template('submit_request.html', user=session['userId'], name=session['username'], submitHandler=submitHandler, instructors = query, account = session['account'])

@app.route('/submit_handler', methods=['POST'])
def submit_handler():
    file = request.files['file']
    if file and extension_check(file.filename):
        header = file.headers['Content-Type']
        blob_string = parse_options_header(header)[1]['blob-key']
        blob_string = blob_string.replace("encoded_gs_file:","")
        blob_key = BlobKey(blob_string)
        supportingDocument = SupportingDocument(
            user = session['userId'],
            blob_key=blob_key
        )
        supportingDocument.put()

        requestId = str(uuid.uuid4())
        submit = submit_form(id =requestId, email = request.form['email'], name = request.form['name'], reason = request.form['reason'], instructor = request.form['instructor'], description = request.form['description'], file_key = blob_key)

        #Instructor Email
        instructorMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - New Submission")
        instructorMessage.to = request.form['instructor']
        instructorMessage.html = """<h1 style='text-align: center'>MitCircs - New Request</h1>
        <p style='text-align: center'>Hello """ + request.form['instructor'] + """! 
        <br> <br> You have recieved a new request from:
        <br> <b>""" + request.form['email'] + """</b>
        <br> <br> Request ID: 
        <br> <b>""" + requestId + """</b>
        <br> <br> To view this submission, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on "manage requests".
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        #Email Reciept
        studentMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Submission Reciept")
        studentMessage.to = request.form['email']
        studentMessage.html = """<h1 style='text-align: center'>MitCircs - Submission Reciept</h1>
        <p style='text-align: center'>Hello """ + request.form['email'] + """! 
        <br> <br> This email is your reciept for your request to:
        <br> <b>""" + request.form['instructor'] + """</b>
        <br> <br> Request ID: 
        <br> <b>""" + requestId + """</b>
        <br> <br> To view this submission, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on "manage requests".
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            instructorMessage.send()
            studentMessage.send()
        except:
            session['failure'] = "Failed to send email to instructor or student. Please check the submission in Manage Requests"
            return render_template('submit_handler.html')

        if submit is not None:
            session['success'] = "The form has been submitted!"
    else:
        session['failure'] = "There was an error submitting the form. Please ensure all fields are filled correctly and the file extension is accepted."
    
    return render_template('submit_handler.html')

@app.route('/manage_requests', methods=['GET', 'POST'])
def manage_requests():
    query = Request.query(Request.email == session['userId'])
    return render_template('manage_requests.html', requests = query, account = session['account'])

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    return render_template('settings.html')

@app.route('/settings_handler', methods=['GET', 'POST'])
def settings_handler():
    if request.form['action'] == "activate_instructor_code":
        code = request.form['instructor_key']
        insCode = InstructorCode.query().filter(ndb.StringProperty("uuid") == code).get()
        if insCode == None:
            session['failure'] = "That code does not appear to be valid. Please ensure you typed it correctly."
            return redirect(url_for('dashboard'))
        else:
            insCode.user_id = session['userId']
            insCode.put()

        user = User.query().filter(ndb.StringProperty("id") == session['userId']).get()
        user.account = "instructor"
        user.put()
        session['success'] = "Your account has been updated to an instructor account"
        return redirect(url_for('dashboard'))
    elif request.form['action'] == "activate_admin_code":
        code = request.form['admin_key']
        admCode = AdminCode.query().filter(ndb.StringProperty("uuid") == code).get()
        if admCode == None:
            session['failure'] = "That code does not appear to be valid. Please ensure you typed it correctly."
            return redirect(url_for('dashboard'))
        else:
            admCode.user_id = session['userId']
            admCode.put()

        user = User.query().filter(ndb.StringProperty("id") == session['userId']).get()
        user.account = "admin"
        user.put()
        session['success'] = "Your account has been updated to an admin account"   
        return redirect(url_for('dashboard'))



@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    users = User.query(User.id == session['userId'])
    for user in users:
        if user.account == "admin":
            return render_template('admin_panel.html')
        else:
            session["failure"] = "You do not have admin rights. Please contact your system administrator if you believe this is incorrect."
            return redirect(url_for('dashboard'))

@app.route('/admin_handler', methods=['GET', 'POST'])
def admin_handler():
    if request.form['action'] == "send_instructor_code":
        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Instructor Code")
        message.to = request.form['email']

        generatedCode = str(uuid.uuid4())

        instructorCode = InstructorCode(user_id = None, uuid = generatedCode).put()

        message.html = """<h1 style='text-align: center'>MitCircs Instructor Code</h1>
        <p style='text-align: center'>Hello """ + request.form['email'] + """! 
        <br> The following instructor code has been generated for you:
        <br> <br> <b>""" + str(generatedCode) + """</b>
        <br> <br> To use this code, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a>, click on Settings and enter the code under the 'Instructor Code' section.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            message.send()
            session['success'] = "Email sent!"
            return redirect(url_for('dashboard'))
        except:
            session['failure'] = "There was an error sending the email. This could be due to a server error. Please try again in a few minutes." 
            return redirect(url_for('dashboard'))  
        
    elif request.form['action'] == "send_admin_code":
        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Admin Code")
        message.to = request.form['email']

        generatedCode = str(uuid.uuid4())

        adminCode = AdminCode(user_id = None, uuid = generatedCode).put()

        message.html = """<h1 style='text-align: center'>MitCircs Admin Code</h1>
        <p style='text-align: center'>Hello """ + request.form['email'] + """! 
        <br> The following admin code has been generated for you:
        <br> <br> <b>""" + str(generatedCode) + """</b>
        <br> <br> To use this code, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a>, click on Settings and enter the code under the 'Admin Code' section.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            message.send()
            session['success'] = "Email sent!"
            return redirect(url_for('dashboard'))
        except:
            session['failure'] = "There was an error sending the email. This could be due to a server error. Please try again in a few minutes."
            return redirect(url_for('dashboard'))

    elif request.form['action'] == "revoke_instructor_code":
        email = request.form['email']
        insCode = InstructorCode.query().filter(ndb.StringProperty("user_id") == email).get()
        if insCode == None:
            session['failure'] = "No email linked to an instructor code could be found"
            return redirect(url_for('dashboard'))
        else:
            insCode.key.delete()

        user = User.query().filter(ndb.StringProperty("id") == email).get()
        user.account = "student"
        user.put()

        session['success'] = "Instructor code revoked! User has been set to account type student"
        return redirect(url_for('dashboard'))
    
    elif request.form['action'] == "revoke_admin_code":
        email = request.form['email']
        admCode = AdminCode.query().filter(ndb.StringProperty("user_id") == email).get()
        if admCode == None:
            session['failure'] = "No email linked to an admin code could be found"
            return redirect(url_for('dashboard'))
        else:
            admCode.key.delete()

        user = User.query().filter(ndb.StringProperty("id") == email).get()
        user.account = "student"
        user.put()

        session['success'] = "Admin code revoked! User has been set to account type student"
        return redirect(url_for('dashboard'))

def signOut():
    session.clear()
    return render_template('sign-out.html')

@app.route('/sign-out')
def signOut():
    session.clear()
    return render_template('sign-out.html')

#Resigtser user after logging in via Firebase
def registerUser(email, name):
    user = User.query(User.id == email).count()
    if user >= 1:
        return None
    else:
        user = User(id = email, name = name, account = "student")
        return user.put()

def submit_form(id, email, name, reason, instructor, description, file_key):
    request = Request(uuid = id, email = email, name = name, reason = reason, instructor = instructor, description = description, file_key = file_key, status = "Awaiting Review")
    return request.put()

def extension_check(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(500)
def server_error(e):
    # Log the error and stacktrace.
    logging.exception('An error occurred during a request.')
    return 'An internal error occurred.', 500
    
if __name__=='__main__':
    app.run(debug=True)