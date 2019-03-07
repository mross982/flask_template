from flask_mail import Message
from app import mail, app
from flask import render_template
from threading import Thread


'''
Python has support for running asynchronous tasks, actually in more than one way. The threading 
and multiprocessing modules can both do this. Starting a background thread for email being sent 
is much less resource intensive than starting a brand new process, so I'm going to go with that 
approach:
When working with threads there is an important design aspect of Flask that needs to be kept in 
mind. Flask uses contexts to avoid having to pass arguments across functions. I'm not going to 
go into a lot of detail on this, but know that there are two types of contexts, the application 
context and the request context. In most cases, these contexts are automatically managed by the 
framework, but when the application starts custom threads, contexts for those threads may need 
to be manually created.
'''
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start() # starts the background thread by calling the above function

def send_password_reset_email(user):
	'''
	The interesting part in this function is that the text and HTML content for the emails 
	is generated from templates using the familiar render_template() function. The templates
	receive the user and the token as arguments, so that a personalized email message can be 
	generated.
	'''
	token = user.get_reset_password_token()
	send_email('[Microblog] Reset Your Password',
			sender=app.config['ADMINS'][0],
			recipients=[user.email],
			text_body=render_template('email/reset_password.txt',
			user=user, token=token),
			html_body=render_template('email/reset_password.html',
			user=user, token=token))


