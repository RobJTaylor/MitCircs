from google.appengine.ext.webapp.mail_handlers import InboundMailHandler
from google.appengine.ext import ndb, blobstore, webapp
from google.appengine.api import mail
from validate_email import validate_email
from google.appengine.ext.blobstore import BlobKey
import webapp2
import main
import uuid

#Our mail handler class
class InboundMail(InboundMailHandler):
    #We override the recieve method
    def receive(self, mail_message):
        #Check that the subject contains a valid email address
        email_valid = validate_email(mail_message.subject)
        #If it does then proceed to assign the request
        if email_valid == True:
            #Make sure instructor is lower-case otherwise it is not assigned properly
            instructor = str(mail_message.subject)
            instructor = str.lower(instructor)
            #Generate a fake BlobKey to not upset GAE - this should be restructured in future
            blob_key = BlobKey("null")
            #Generate a horrible uuid index for the request
            requestId = str(uuid.uuid4())

            #Get the body from the email as plain text - this acts as our request desciption
            decodedBody = ''
            textBody = mail_message.bodies('text/plain')
            for content_type, body in textBody:
                decodedBody = body.decode()
            
            #Submit the request
            main.submit_form(requestId, str(mail_message.sender), str(mail_message.sender), "other", instructor, str(decodedBody), blob_key, "email")

            #Inform the instructor they have a new request
            instructorMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - New Submission")
            instructorMessage.to = instructor
            instructorMessage.html = """<h1 style='text-align: center'>MitCircs - New Request</h1>
            <br> <p style='text-align: center'> You have recieved a new request from:
            <br> <b>""" + str(mail_message.sender) + """</b>
            <br> <br> Request ID:
            <br> <br> <b>""" + requestId + """</b>
            <br> <br> To view this submission, please login to <a href='https://mitcircs.robtaylor.info'>MitCircs</a> and click on "manage requests".
            <br> <br> Thanks,
            <br> The MitCircs Team </p>"""
            instructorMessage.send()
        #The subject doesn't contain a valid email - inform the student of this and don't assign the request
        else:
            studentMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Submission Error")
            studentMessage.to = mail_message.sender
            studentMessage.html = """<h1 style='text-align: center'>MitCircs - Submission Error</h1>
            <br> <p style='text-align: center'> Your email submission has not been logged. Please ensure you include your instructor's email in the subjext line.
            <br> <br> Thanks,
            <br> The MitCircs Team</p>"""
            studentMessage.send()

app = webapp2.WSGIApplication([InboundMail.mapping()], debug=True)