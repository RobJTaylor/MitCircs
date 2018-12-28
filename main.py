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

ALLOWED_EXTENSIONS = set (['doc', 'docx', 'pdf', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mitcircs_super_secret_key'

requests_toolbelt.adapters.appengine.monkeypatch()
HTTP_REQUEST = google.auth.transport.requests.Request()

class User(ndb.Model):
    name = ndb.StringProperty()
    account = ndb.StringProperty()

class Request(ndb.Model):
    email = ndb.StringProperty()
    name = ndb.StringProperty()
    reason = ndb.StringProperty()
    instructor = ndb.StringProperty()
    description = ndb.StringProperty()
    file_key = ndb.BlobKeyProperty()

class SupportingDocument(ndb.Model):
    user = ndb.StringProperty()
    blob_key = ndb.BlobKeyProperty()

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
    if session['userId'] == None:
        session['error'] = 1
        return redirect(url_for('index'))

    if session.get('success'):
        session['success'] = None
        return render_template('dashboard.html', user=session['userId'], name=session['username'], success=1)
    elif session.get('failure'):
        session['failure'] = None
        return render_template('dashboard.html', user=session['userId'], name=session['username'], failure=1)

    return render_template('dashboard.html', user=session['userId'], name=session['username'])

@app.route('/submit_request', methods=['GET', 'POST'])
def submit_request():
    upload = blobstore.create_upload_url('/submit_handler', gs_bucket_name="mitcircs-rt")
    return render_template('submit_request.html', user=session['userId'], name=session['username'], upload=upload)

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
        submit = submit_form(email = request.form['email'], name = request.form['name'], reason = request.form['reason'], instructor = request.form['instructor'], description = request.form['description'], file_key = blob_key)
        if submit is not None:
            session['success'] = 1
    else:
        session['failure'] = 1
    return render_template('submit_handler.html')

@app.route('/manage_requests', methods=['GET', 'POST'])
def manage_requests():
    return render_template('manage_requests.html')

@app.route('/sign-out')
def signOut():
    session.clear()
    return render_template('sign-out.html')

#Resigtser user after logging in via Firebase
def registerUser(email, name):
    user = User(id = email, name = name, account = "student")
    return user.put()

def submit_form(email, name, reason, instructor, description, file_key):
    request = Request(email = email, name = name, reason = reason, instructor = instructor, description = description, file_key = file_key)
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