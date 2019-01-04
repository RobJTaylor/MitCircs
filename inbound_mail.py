from google.appengine.ext.webapp.mail_handlers import InboundMailHandler
from google.appengine.ext import ndb, blobstore, webapp
from google.appengine.api import mail
import webapp2

class InboundMail(InboundMailHandler):
    def receive(self, mail_message):
        #Instructor Email
        instructorMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - New Submission")
        instructorMessage.to = mail_message.subject
        instructorMessage.html = """<h1 style='text-align: center'>MitCircs - New Request</h1>"""

        try:
            instructorMessage.send()
        except:
            studentMessage = mail.EmailMessage(sender="MitCircs <robert.j.taylor117@gmail.com>", subject="MitCircs - Submission Error")
            studentMessage.to = mail_message.sender
            studentMessage.html = """<h1 style='text-align: center'>MitCircs - Submission Error</h1>
            <br> <br> Your email submission has not been logged. Please ensure you include your instructor's email in the subjext line.
            <br> <br> Thanks,
            <br> The MitCircs Team"""
            studentMessage.send()

app = webapp2.WSGIApplication([InboundMail.mapping()], debug=True)
