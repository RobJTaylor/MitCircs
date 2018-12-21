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
import webapp2, logging
from flask import Flask, jsonify, request, render_template, redirect, url_for, g
import flask_cors
from google.appengine.ext import ndb
import google.auth
import google.auth.transport.requests
import google.oauth2.id_token
import requests_toolbelt.adapters.appengine

app = Flask(__name__)

requests_toolbelt.adapters.appengine.monkeypatch()
HTTP_REQUEST = google.auth.transport.requests.Request()

class User(ndb.Model):
    name = ndb.StringProperty()
    account = ndb.StringProperty()

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'Authorization' in request.headers:
        id_token = request.headers['Authorization'].split(' ').pop()
        email = request.headers['Email'].split(' ').pop()
        name = request.headers['Username'].split(' ').pop()
        claims = google.oauth2.id_token.verify_firebase_token(id_token, HTTP_REQUEST)
        if claims:
            user_id = registerUser(email, name)
            logging.exception(user_id)
            return 'authorized', 402
        else:
            return 'Not authorized', 401     
    else:
        return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render_template('dashboard.html')

def registerUser(email, name):
    user = User(id = email, name = name, account = "student")
    return user.put()

@app.errorhandler(500)
def server_error(e):
    # Log the error and stacktrace.
    logging.exception('An error occurred during a request.')
    return 'An internal error occurred.', 500
    
if __name__=='__main__':
    app.secret_key = 'mitcircs_super_secret_key'
    app.run(debug=True)