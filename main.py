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
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, make_response
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

#Allowed supporting file extensions
ALLOWED_EXTENSIONS = set (['doc', 'docx'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mitcircs_super_secret_key'

requests_toolbelt.adapters.appengine.monkeypatch()
HTTP_REQUEST = google.auth.transport.requests.Request()

#User - gets initial data from Firebase
class User(ndb.Model):
    id = ndb.StringProperty()
    name = ndb.StringProperty()
    account = ndb.StringProperty()

#Request - made when student submits mitigating circumstances
class Request(ndb.Model):
    email = ndb.StringProperty()
    name = ndb.StringProperty()
    reason = ndb.StringProperty()
    instructor = ndb.StringProperty()
    description = ndb.StringProperty()
    file_key = ndb.BlobKeyProperty()
    status = ndb.StringProperty()
    uuid = ndb.StringProperty()
    requestedInfo = ndb.StringProperty()
    studentResponse = ndb.StringProperty()

#SupportingDocument - uploaded when student makes request
class SupportingDocument(ndb.Model):
    user = ndb.StringProperty()
    blob_key = ndb.BlobKeyProperty()

#InstructorCode - code that can be used to make account instructor
class InstructorCode(ndb.Model):
    user_id = ndb.StringProperty()
    uuid = ndb.StringProperty()

#AdminCode - code that can be used to make account admin
class AdminCode(ndb.Model):
    user_id = ndb.StringProperty()
    uuid = ndb.StringProperty()

@app.route('/', methods=['GET', 'POST'])
def index():
    #Reset important session vars when heading back to login page
    session['userId'] = None
    session['username'] = None

    #Display error if we encounter one
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
        #We're authorised!
        if claims:
            user_id = registerUser(email, name)
            return 'authorized'
        #We're not authorised
        else:
            return 'Not authorized', 401     
    else:
        return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    requestQuery = Request.query(Request.email == session['userId'])
    userQuery = User.query(User.id == session['userId'])

    #Account type defines what the dashboard page looks like
    for user in userQuery:
        session['account'] = user.account

    #If we're not actually logged in send us back
    if session['userId'] == None:
        session['error'] = 1
        return redirect(url_for('index'))

    #Display success or error messages based on vars passed through
    if session.get('success'):
        success = session['success']
        session['success'] = None
        return render_template('dashboard.html', user=session['userId'], name=session['username'], success=success, account = session['account'])
    elif session.get('failure'):
        failure = session['failure']
        session['failure'] = None
        return render_template('dashboard.html', user=session['userId'], name=session['username'], failure=failure, account = session['account'])

    return render_template('dashboard.html', user=session['userId'], name=session['username'], requests=requestQuery, account = session['account'])

#The actual page the student uses when submitting a request
@app.route('/submit_request', methods=['GET', 'POST'])
def submit_request():
    #Setup blobstore URL for file upload
    submitHandler = blobstore.create_upload_url('/submit_handler', gs_bucket_name="mitcircs")
    
    #Check if any instructors are setup, return None if none exist
    query = User.query(User.account == "instructor")
    for instructor in query:
        if instructor.id == "":
            return render_template('submit_request.html', user=session['userId'], name=session['username'], submitHandler=submitHandler, instructors = None, account = session['account'])

    return render_template('submit_request.html', user=session['userId'], name=session['username'], submitHandler=submitHandler, instructors = query, account = session['account'])

#We come here from /submit_request, this is where the main logic lies
@app.route('/submit_handler', methods=['POST'])
def submit_handler():
    #First let's deal with the submitted file
    file = request.files['file']
    #Check the filetype is allowed (doc, docx only)
    if file and extension_check(file.filename):
        #Get file type, generate BlobKey and create supportingDocument object
        header = file.headers['Content-Type']
        blob_string = parse_options_header(header)[1]['blob-key']
        blob_key = BlobKey(blob_string)
        supportingDocument = SupportingDocument(
            user = session['userId'],
            blob_key=blob_key
        )
        #Make sure we save the object
        supportingDocument.put()

        #Using a UUID as an index... see assignment write-up for why. Sorry in advance!
        requestId = str(uuid.uuid4())

        #Send all our form data to submit_form
        submit = submit_form(id =requestId, email = request.form['email'], name = request.form['name'], reason = request.form['reason'], instructor = request.form['instructor'], description = request.form['description'], file_key = blob_key, requestType = "")

        #Now let's notify the instructor that they have a new request
        #Personal email address is used, sorry about that!
        instructorMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - New Submission")
        instructorMessage.to = request.form['instructor']
        #Using some HTML with formatting to make the email less bland
        instructorMessage.html = """<h1 style='text-align: center'>MitCircs - New Request</h1>
        <p style='text-align: center'>Hello """ + request.form['instructor'] + """! 
        <br> <br> You have recieved a new request from:
        <br> <b>""" + request.form['email'] + """</b>
        <br> <br> Request ID: 
        <br> <b>""" + requestId + """</b>
        <br> <br> To view this submission, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on "manage requests".
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        #Now let's notify the student that they submitted the request correctly
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

        #Attempt to send both emails, return to dashboard with error if this doesn't happen
        try:
            instructorMessage.send()
            studentMessage.send()
        except:
            session['failure'] = "Failed to send email to instructor or student. Please check the submission in Manage Requests"
            return render_template('submit_handler.html')

        if submit is not None:
            session['success'] = "The form has been submitted!"
    #Student submitted an incorrect file, inform them of their mistake
    else:
        session['failure'] = "There was an error submitting the form. Please ensure all fields are filled correctly and the file extension is accepted."
    
    return redirect(url_for('dashboard'))

#Standard manage requests page accessed by both students and instructors
@app.route('/manage_requests', methods=['GET', 'POST'])
def manage_requests():
    #Query either:
    #   Reqests matching student's ID
    #   Requests matching instructor's ID
    #Based on account type
    if session['account'] == "student":
        query = Request.query(Request.email == session['userId'])
    elif session['account'] == "instructor":
        query = Request.query(Request.instructor == session['userId'])

    return render_template('manage_requests.html', requests = query, account = session['account'])

#Manage requests page accessed only by instructors looking at all requests awaiting review
@app.route('/manage_requests_ar', methods=['GET', 'POST'])
def manage_requests_ar():
    #Query on both account ID and request status
    query = Request.query(Request.instructor == session['userId'], Request.status == "Awaiting Review")
    return render_template('manage_requests.html', requests = query, account = session['account'])

#Settings page accessed by everybody, used to activate admin and instructor codes
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    return render_template('settings.html')

#Settings handler is the logic behind activating codes. We get here after using the settings page.
@app.route('/settings_handler', methods=['GET', 'POST'])
def settings_handler():
    #If we want to activate an instructor code
    if request.form['action'] == "activate_instructor_code":
        #Get the code entered by the user, get the entity from InstructorCode
        code = request.form['instructor_key']
        insCode = InstructorCode.query().filter(ndb.StringProperty("uuid") == code).get()

        #If the query comes back empty there's a typo or user is trying to become an instructor without a code. Inform them appropriately.
        if insCode == None:
            session['failure'] = "That code does not appear to be valid. Please ensure you typed it correctly."
            return redirect(url_for('dashboard'))
        #If everything checks out tie user's ID to the code
        else:
            insCode.user_id = session['userId']
            insCode.put()

        #Actually give the user instructor privelidges
        user = User.query().filter(ndb.StringProperty("id") == session['userId']).get()
        user.account = "instructor"
        user.put()

        #Let them know everything went swimmingly
        session['success'] = "Your account has been updated to an instructor account"
        return redirect(url_for('dashboard'))
    #If we want to activate an admin code
    elif request.form['action'] == "activate_admin_code":
        #The below code follows the same path/logic as the intructor code above. 
        #Imagine all the above comments say "admin" instead of "instructor" and place them appropriately.
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

#The admin panel page
@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    #Do a quick query to check the user actually has admin status
    users = User.query(User.id == session['userId'])
    for user in users:
        #Let them through is everything checks out
        if user.account == "admin":
            return render_template('admin_panel.html')
        #Or give them a slap on the wrist
        else:
            session["failure"] = "You do not have admin rights. Please contact your system administrator if you believe this is incorrect."
            return redirect(url_for('dashboard'))

#The admin handler accessed from the admin panel page. Apologies for the wall of logic below.
@app.route('/admin_handler', methods=['GET', 'POST'])
def admin_handler():
    #We want to send an instructor code
    if request.form['action'] == "send_instructor_code":
        #Setup the email
        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Instructor Code")
        message.to = request.form['email']
        #Generate the code via uuid
        generatedCode = str(uuid.uuid4())
        #Pop the code into the datastore, ignore the user's email for now
        instructorCode = InstructorCode(user_id = None, uuid = generatedCode).put()
        #Make the email look nice
        message.html = """<h1 style='text-align: center'>MitCircs Instructor Code</h1>
        <p style='text-align: center'>Hello """ + request.form['email'] + """! 
        <br> The following instructor code has been generated for you:
        <br> <br> <b>""" + str(generatedCode) + """</b>
        <br> <br> To use this code, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a>, click on Settings and enter the code under the 'Instructor Code' section.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""
        #Attempt to send or inform of failure
        try:
            message.send()
            session['success'] = "Email sent!"
            return redirect(url_for('dashboard'))
        except:
            session['failure'] = "There was an error sending the email. This could be due to a server error. Please try again in a few minutes." 
            return redirect(url_for('dashboard'))  
    #We want to send an admin code
    elif request.form['action'] == "send_admin_code":
        #Again the below code path/logic follows the instructor code, just for admin code instead
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
    #We want to revoke instructor rights
    elif request.form['action'] == "revoke_instructor_code":
        #Get the user's email and query the InstructorCode entities for the email
        email = request.form['email']
        insCode = InstructorCode.query().filter(ndb.StringProperty("user_id") == email).get()

        #If we can't find the user inform the admin
        if insCode == None:
            session['failure'] = "No email linked to an instructor code could be found"
            return redirect(url_for('dashboard'))
        #If we've found the user delete the instructor code
        else:
            insCode.key.delete()

        #Set user's account type back to student
        user = User.query().filter(ndb.StringProperty("id") == email).get()
        user.account = "student"
        user.put()

        session['success'] = "Instructor code revoked! User has been set to account type student"
        return redirect(url_for('dashboard'))
    #We want to revoke admin rights
    elif request.form['action'] == "revoke_admin_code":
        #The below code logic follows the same as the instructor logic above.
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

#Used to update student's mitcirc request
@app.route('/update_request', methods=['GET', 'POST'])
def updateRequest():
    #We want to accept the request
    if request.form['action'] == "accept_request":
        #Get & set the request to approved
        userRequest = Request.query().filter(ndb.StringProperty("uuid") == request.form['request_id']).get()
        userRequest.status = "Approved"
        userRequest.put()

        #Let the student know the request was accepted
        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Request Accepted")
        message.to = userRequest.email
        message.html = """<h1 style='text-align: center'>MitCircs Request Accepted</h1>
        <p style='text-align: center'>Hello """ + userRequest.email + """! 
        <br> <br> Your request has been approved!
        <br> <br> Request ID: <b>
        <br>""" + userRequest.uuid + """</b>
        <br> <br> To view this request, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on manage requests.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            message.send()
        except:
            session['failure'] = "Error sending student notification email. Please check request status in manage requests."
            return redirect(url_for('dashboard'))
        
        session['success'] = "Request accepted! Student has been sent a notification email."
        return redirect(url_for('dashboard'))
    #We want to decline the request
    elif request.form['action'] == "decline_request":
        #The below code follows the same as accept request but it declines the request instead
        userRequest = Request.query().filter(ndb.StringProperty("uuid") == request.form['request_id']).get()
        userRequest.status = "Declined"
        userRequest.put()

        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Request Declined")
        message.to = userRequest.email

        message.html = """<h1 style='text-align: center'>MitCircs Request Accepted</h1>
        <p style='text-align: center'>Hello """ + userRequest.email + """! 
        <br> <br> Your request has been declined.
        <br> <br> Request ID: <b>
        <br>""" + userRequest.uuid + """</b>
        <br> <br> Contact your course instructor for further information on this decision.
        <br> To view this request, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on manage requests.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            message.send()
        except:
            session['failure'] = "Error sending student notification email. Please check request status in manage requests."
            return redirect(url_for('dashboard'))
    
        session['success'] = "Request declined. Student has been sent a notification email."
        return redirect(url_for('dashboard'))
    #We want to request more info from the student
    elif request.form['action'] == "request_info":
        #Set the request status to info required
        userRequest = Request.query().filter(ndb.StringProperty("uuid") == request.form['request_id']).get()
        userRequest.status = "Info Required"
        userRequest.requestedInfo = request.form['infoRequired']
        userRequest.put()

        #Let the student know of this decision
        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Info Needed")
        message.to = userRequest.email
        message.html = """<h1 style='text-align: center'>MitCircs Info Needed</h1>
        <p style='text-align: center'>Hello """ + userRequest.email + """! 
        <br> <br> Your instructor has requested more information for your request.
        <br> <br> Request ID: <b>
        <br>""" + userRequest.uuid + """</b>
        <br> <br> Instructor comments:
        <br>""" + request.form['infoRequired'] + """
        <br> <br> To view this request, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on manage requests.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            message.send()
        except:
            session['failure'] = "Error sending student notification email. Please check request status in manage requests."
            return redirect(url_for('dashboard'))

        session['success'] = "Update requested. Student has been sent a notification email."
        return redirect(url_for('dashboard'))
    #Student wants to update their request - used after instructor has requested more info
    elif request.form['action'] == "update_info":
        #Set request back to awaiting review
        userRequest = Request.query().filter(ndb.StringProperty("uuid") == request.form['request_id']).get()
        userRequest.studentResponse = request.form['studentResponse']
        userRequest.status = "Awaiting Review"
        userRequest.put()

        #Inform instructor the student updated the request
        message = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Student Response")
        message.to = userRequest.instructor
        message.html = """<h1 style='text-align: center'>MitCircs Student Response</h1>
        <p style='text-align: center'>Hello """ + userRequest.instructor + """! 
        <br> <br> Your student has provided more information on their request.
        <br> <br> Request ID: <b>
        <br>""" + userRequest.uuid + """</b>
        <br> <br> Student comments:
        <br>""" + request.form['studentResponse'] + """
        <br> <br> To view this request, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on manage requests.
        <br> <br> Thanks,
        <br> The MitCircs Team </p>"""

        try:
            message.send()
        except:
            session['failure'] = "Error sending instructor notification email. Please check request status in manage requests."
            return redirect(url_for('dashboard'))

        session['success'] = "Information updated. Instructor notified."
        return redirect(url_for('dashboard'))

#Instructor comes here when they want to request more info from student
@app.route('/request_info', methods=['GET', 'POST'])
def requestInfo():
    userRequest = Request.query().filter(ndb.StringProperty("uuid") == request.form['request_id']).get()
    return render_template('request_info.html', userRequest = userRequest)

#Used to view/add more info to the request
@app.route('/view_request', methods=['GET', 'POST'])
def viewRequest():
    userRequest = Request.query().filter(ndb.StringProperty("uuid") == request.form['request_id']).get()

    if request.form['action'] != None:
        action = request.form['action']
    else:
        action = ""

    return render_template('view_request.html', userRequest = userRequest, action = action)

#Serve files from blobstore
@app.route('/serve/<blobKey>', methods=['GET', 'POST'])
def serve(blobKey):
    blobInfo = blobstore.get(blobKey)
    response = make_response(blobInfo.open().read())
    response.headers['Content-Type'] = blobInfo.content_type
    return response

#Actually let the user sign out
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

#Called from submit request page - actual logic to submit the request
def submit_form(id, email, name, reason, instructor, description, file_key, requestType):
    #If the request is via email we don't store any files
    if requestType == "email":
        request = Request(uuid = id, email = email, name = name, reason = reason, instructor = instructor, description = description, file_key = file_key, status = "Awaiting Review")
    #If it's a standard request store the file too
    else:
        request = Request(uuid = id, email = email, name = name, reason = reason, instructor = instructor, description = description, status = "Awaiting Review")

    return request.put()

#Check file extension to make sure it's allowed
def extension_check(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#Print error info
@app.errorhandler(500)
def server_error(e):
    # Log the error and stacktrace.
    logging.exception('An error occurred during a request.')
    return 'An internal error occurred.', 500
    
if __name__=='__main__':
    app.run(debug=True)