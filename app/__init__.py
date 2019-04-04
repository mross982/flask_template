from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from config import Config
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask import request

# line below (and from app inport routes) is all you need for a basic app
app = Flask(__name__)
# creates the application object as an instance of class Flask imported from the flask package.

app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app) # ensures content cannot be viewed if user is not logged in.
login.login_view = 'login'
# The 'login' value above is the function (or endpoint) name for the login view. In other words, 
# the name you would use in a url_for() call to get the URL.
mail = Mail(app)
bootstrap = Bootstrap(app)
moment = Moment(app) # unlike other extensions, moment works with moment.js
# Moment.js makes a moment class available to the browser.


# app is the package; routes, models, etc. are the modules
from app import routes, models, errors, forms
'''
One aspect that may seem confusing at first is that there are two entities named app. 
The app package is defined by the app directory and the __init__.py script, and is 
referenced in the from app import routes statement. The app variable is defined as an 
instance of class Flask in the __init__.py script, which makes it a member of the app 
package.
'''

import logging
from logging.handlers import SMTPHandler, RotatingFileHandler
import os


if not app.debug: # below is for logging errors
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/microblog.log', maxBytes=10240,
                                       backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO) #they are DEBUG, INFO, WARNING, ERROR and CRITICAL
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('Microblog startup')

    # Below is for email debugging
    if app.config['MAIL_SERVER']:
        auth = None
        if app.config['MAIL_USERNAME'] or app.config['MAIL_PASSWORD']:
            auth = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        secure = None
        if app.config['MAIL_USE_TLS']:
            secure = ()
        mail_handler = SMTPHandler(
            mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
            fromaddr='no-reply@' + app.config['MAIL_SERVER'],
            toaddrs=app.config['ADMINS'], subject='Microblog Failure',
            credentials=auth, secure=secure)
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

'''
the code above creates a SMTPHandler instance, sets its level so that it only reports 
errors and not warnings, informational or debugging messages, and finally attaches it 
to the app.logger object from Flask.

There are two approaches to test this feature. The easiest one is to use the SMTP 
debugging server from Python. This is a fake email server that accepts emails, but 
instead of sending them, it prints them to the console. To run this server, open a 
second terminal session and run the following command on it:

(venv) $ python -m smtpd -n -c DebuggingServer localhost:8025

Leave the debugging SMTP server running and go back to your first terminal and set 
MAIL_SERVER=localhost and and MAIL_PORT=8025 in the environment. Make sure the FLASK_DEBUG 
variable is set to 0

SETTINGS FOR GMAIL
(venv) $ set MAIL_SERVER=smtp.googlemail.com
(venv) $ set MAIL_PORT=587
(venv) $ set MAIL_USE_TLS=1
(venv) $ set MAIL_USERNAME=<your-gmail-username>
(venv) $ set MAIL_PASSWORD=<your-gmail-password>

Remember that the security features in your Gmail account may prevent the application from 
sending emails through it unless you explicitly allow "less secure apps" access to your Gmail 
account.

(venv) $ flask shell 

>>> from flask_mail import Message
>>> from app import mail
>>> msg = Message('test subject', sender=app.config['ADMINS'][0],
... recipients=['your-email@example.com'])
>>> msg.body = 'text body'
>>> msg.html = '<h1>HTML body</h1>'
>>> mail.send(msg)
'''