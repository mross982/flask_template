from datetime import datetime
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.forms import LoginForm, RegistrationForm, MeasureSetupForm, BenchmarksForm
from app.models import User, Measure, Benchmark, Data
from app.forms import ResetPasswordRequestForm, ResetPasswordForm
from app.email import send_password_reset_email
import sys

'''
These routes are know as the view function
Note the 'Post/Redirect/Get' pattern (even redirect to the same page). This avoids inserting 
duplicate posts when a user refreshes the page after submitting a web form.

The render_template() function invokes the Jinja2 template engine that comes bundled 
with the Flask framework. Jinja2 substitutes {{ ... }} blocks in the template with the 
corresponding values, given by the arguments provided in the render_template() call.
'''

@app.before_request
def before_request():
    '''
    The @before_request decorator from Flask register the decorated function to be executed right 
    before the view function. This is extremely useful because now I can insert code that I want 
    to execute before any view function in the application, and I can have it in a single place. 
    The implementation simply checks if the current_user is logged in, and in that case sets the 
    last_seen field to the current time. 
    '''
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        # the reason db.session.add() is not located here is b/c current_user indicates the database
        # has already been queried that will add the user to the database session.
        db.session.commit()


@app.route('/')
@app.route('/index')
def index():

    return render_template('index.html', title='Statistical Modeling For Your Budget')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/measure_setup', methods=['GET', 'POST'])
@login_required
def measure_setup():
    form = MeasureSetupForm()
    if form.validate_on_submit():
        measure = Measure(name=form.name.data, user_id=current_user.id, unit=form.unit.data, start_date=form.start_date.data,
            end_date=form.end_date.data, direction=form.direction.data)
        db.session.add(measure)
        db.session.commit()
        
        return redirect(url_for('benchmarks', measurename=measure.name))
    print(form.errors)
    return render_template('measure_setup.html', title='Set up a Measure', form=form)


@app.route('/benchmarks/<measurename>', methods=['GET', 'POST'])
@login_required
def benchmarks(measurename):
    form = BenchmarksForm()
    if form.validate_on_submit():
        measure = Measure.query.filter_by(name=measurename).first_or_404()
        for entry in form.benchmark.entries:
            n_bm = Benchmark(measure_id=measure.id, benchmark=entry.data['benchmark'], value=entry.data['value'])
            db.session.add(n_bm)
            db.session.commit()
        flash('New Measure Successfully Added!')
        return redirect(url_for('index'))
    print(form.errors)
    return render_template('benchmarks.html', title=measurename, form=form)


@app.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    measures = Measure.query.filter_by(user_id=user.id).all()

    return render_template('user.html', user=user, measures=measures)


@app.route('/edit_measure/<measure>', methods=['GET', 'POST'])
@login_required
def edit_measure(user, measure):
    form = MeasureSetupForm()
    return render_template('edit_measure.html')



@app.route('/delete_measure/', methods=['GET','POST'])
@login_required
def delete_measure(measure):
    print(measure.name)
    db.session.delete(measure)
    db.session.commit()
    return render_template('user.html')


#*************** Extra Code ************************************************







@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required

def edit_profile():
    form = EditProfileForm(current_user.username) # allows error caused by selecting same username
    # as someone else to be resolved without interference if you enter your current username
    if form.validate_on_submit(): # only returns true if a POST method AND information is validated
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.') # sends text to the flash section of the base template
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET': # if the client is GET info (i.e. first directed to the URL)
        form.username.data = current_user.username # fill in the fields with previously entered data
        form.about_me.data = current_user.about_me # from the database
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)


@app.route('/explore')
@login_required
def explore():
    '''
    Notice the index.html template is reused from '/index' however, there is no form and the posts are not filtered
    '''
    # SCAFFOLDING
    # posts = Post.query.order_by(Post.timestamp.desc()).all()

    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template("index.html", title='Explore', posts=posts.items,
                          next_url=next_url, prev_url=prev_url)



@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot follow yourself!')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('You are following {}!'.format(username))
    return redirect(url_for('user', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You are not following {}.'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    '''
    After the email is sent, I flash a message directing the user to look for the email for further 
    instructions, and then redirect back to the login page. You may notice that the flashed message 
    is displayed even if the email provided by the user is unknown. This is so that clients cannot 
    use this form to figure out if a given user is a member or not.
    '''
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated: #Make sure user isn't logged in
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token) # verify token returning user
    if not user:
        return redirect(url_for('index')) # if the token was not verified, returned None
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)