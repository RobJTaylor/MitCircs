# MitCircs
## Advanced Development - [Bournemouth University] (https://www.bournemouth.ac.uk/) Final Year Submission

# What is MitCircs?
MitCircs is a mitigating circumstances system. It deals with recieving requests (via form or email) and managing those requests. It demonstrates this on a small scale using Google App Engine. There are a couple of large issues with the code (using UUID's instead of ndb's indexing, all code being in main, etc.) but it is fully functional to the assignment specification.

# Main technologies used:
* Google App Engine (GCloud)
* Flask
* Ajax
* Firebase Authentication

# What do I need to do to get it up and running?
You will need to import the project and upload it to Google App Engine. Firebase authentication credentials will need to be replaced with your own generated from https://firebase.google.com/products/auth/. The ndb should set itself up, though you will need to manually set a user's status to admin in the ndb.
