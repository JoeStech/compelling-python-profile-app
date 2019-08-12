from flask import Flask, render_template, request, redirect, url_for, current_app
import boto3
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import requests
import re
import bleach
import sys
import uuid

# This is for the sanitization of user input biographies -- we don't want any executable code in our database.
bleach.sanitizer.ALLOWED_TAGS = bleach.sanitizer.ALLOWED_TAGS.extend(['p', 'br', 'h1', 'h2', 'h3', 'u'])

UPLOAD_FOLDER = '/tmp/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
BUCKET = 'examplebucketname' # REPLACE WITH YOUR BUCKET NAME
DYNAMO_USER_TABLE = 'example_table_name' # REPLACE WITH YOUR TABLE NAME

# app init
app = Flask(__name__)
app.secret_key = b'1656ec44878746679b21' # DO NOT USE THIS FOR YOUR DEPLOY. This is an example that should be changed to a random key.
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# extensions inits
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ROUTES
########

# For an explanation of this function, please see the "Flask" chapter in the Serverless Flask guide at compellingpython.com
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        userid = current_user.id
        name = request.form['author_name']
        bio = request.form['author_bio']
        quill_bio = request.form['quill_bio']

        # check if the post request has the file part
        if 'profile_img' not in request.files:
            return redirect(edit_profile(userid, name, bio, quill_bio))
        else:
            file = request.files['profile_img']
            if file.filename == '':
                return '<h1>Your file does\'t have a filename.</h1>'

            if file and allowed_file(file.filename):
                s3_photo_location = save_photo(file, name, 'authors/images/')
                return redirect(edit_profile(userid, name, bio, quill_bio, s3_photo_location))

    return render_template("edit-page.html")


# For an explanation of this function, please see the "Login Function" subsection of the
# "Registration, authentication, and email confirmation" chapter in the Serverless Flask guide at compellingpython.com
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['author_email']
        password = request.form['author_password']
        if "remember_me" in request.form.keys():
            remember_me = True
        else:
            remember_me = False
        user = User(userid)
        if user.verify_password(password):
            login_user(user, remember_me)
            return redirect(url_for('index'))
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# For an explanation of this function, please see the "Registration and confirmation" subsection of the
# "Registration, authentication, and email confirmation" chapter in the Serverless Flask guide at compellingpython.com
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        userid = request.form['author_email']
        username = request.form['author_name']
        userpassword = request.form['author_password']
        if not new_user(userid,username,userpassword):
            return render_template('notification.html', notification="That email address is already in use.")
        user = User(userid, username)
        token = user.generate_confirmation_token()
        user.email('email/confirmation', 'confirm your email address', user=user, token=token)
        login_user(user)
        return redirect(url_for('index'))
    else:
        return render_template('register.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        if current_user.verify_password(old_password):
            edit_password(current_user.id, new_password)
            return redirect(url_for('index'))
        else:
            return render_template('change-password.html', notification = "<div class='notification is-danger'>wrong current password</div>")
    else:
        return render_template('change-password.html')


# For an explanation of this function, please see the "Registration and confirmation" subsection of the
# "Registration, authentication, and email confirmation" chapter in the Serverless Flask guide at compellingpython.com
@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('index'))
    if current_user.confirm(token):
        return redirect(url_for('index'))
    else:
        return render_template('notification.html', notification="The confirmation link is either invalid or expired.")



# SUPPORTING FUNCTIONS AND CLASSES
##################################


# helper function to limit what types of image files can be uploaded
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# For an explanation of this function, please see the "Flask-Login" subsection of the
# "Registration, authentication, and email confirmation" chapter in the Serverless Flask guide at compellingpython.com
@login_manager.user_loader
def load_user(user_id):
    try:
        return User(user_id)
    except:
        return None


# For an explanation of this function, please see the "Protecting routes" subsection of the
# "Registration, authentication, and email confirmation" chapter in the Serverless Flask guide at compellingpython.com
@app.before_request
def before_request():
    print(request)
    if current_user.is_authenticated and 'confirm' not in request.url_rule.rule:
        if not current_user.confirmed:
            return render_template('notification.html', notification="You must confirm your email address by clicking the link sent to you via email.")
        if not current_user.publisher_confirmed:
            return render_template('notification.html', notification="You must wait to have your account approved by the publisher.")


# helper function to upload profile pictures to a unique location in S3
def save_photo(file, name, s3_photo_root):
    s3 = boto3.client('s3')
    hexkey = uuid.uuid4().hex
    filename = secure_filename(file.filename) + hexkey
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    s3_photo_location = s3_photo_root + '-'.join(name.split(' ')).lower() + hexkey
    s3.upload_file(os.path.join('/tmp/',filename), 'compellingsciencefiction.com', s3_photo_location)
    return s3_photo_location


# This function creates a new user in DynamoDB.
# If you'd like to learn a little more about DynamoDB, you can check out the "DynamoDB" chapter in the Serverless Flask guide at compellingpython.com
def new_user(userid, username, userpassword):
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(DYNAMO_USER_TABLE)
    item = table.get_item(Key={'author_email': userid})
    if 'Item' in item:
        return False

    password_hash = generate_password_hash(userpassword)

    table_item = {
                'author_email': userid,
                'username': username,
                'password_hash': password_hash,
                'bio': "none",
                'photo_location': "none",
                'page_location': "none",
                'email_confirmed': False,
                'csf_approved': False
            }

    table.put_item(Item=table_item)
    return True


def edit_password(userid, password):
    """
    This is a helper function used by the password edit view function. It just changes the password in the database.
    If you'd like to learn a little more about DynamoDB, you can check out the "DynamoDB" chapter in the Serverless Flask guide at compellingpython.com
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(DYNAMO_USER_TABLE)

    password_hash = generate_password_hash(password)

    expression = "SET password_hash = :password_hash"
    values = {":password_hash":password_hash}

    table.update_item(Key={'author_email': userid},
               UpdateExpression=expression,
               ExpressionAttributeValues=values)


def edit_profile(userid, username, userbio, quill_bio, userimgname=None):
    """
    This is a mildly complicated function that is used to edit a user's profile. The tricky parts involve making sure that
    multiple people with the same name get different bio pages in S3.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(DYNAMO_USER_TABLE)
    userbio = bleach.clean(userbio, strip=True)
    quill_bio = bleach.clean(quill_bio, strip=True)

    s3_path = 'authors/'+username.replace(" ", "-").replace(".","").lower()+".html"

    item = table.get_item(Key={'author_email': userid})['Item']
    
    if 'page_location' in item and item['page_location'] != 'none':
        s3_path = item['page_location']
    else:
        # make sure we don't overwrite someone else's bio by extracting a number from the URL and incrementing it
        r = requests.get("http://compellingsciencefiction.com/" + s3_path)
        if r.status_code == 200:
            author_number = ""
            match = re.search('[0-9]+',s3_path)
            if match:
                existing_number = match.group(0)
                author_number = str(int(existing_number)+1)
            else:
                author_number = "2"
            s3_path = 'authors/'+username.replace(" ", "-").replace(".","").lower()+ author_number +".html"

    if 'photo_location' in item and userimgname and item['photo_location'] != 'none':
        s3 = boto3.client('s3')
        s3.delete_object(Bucket=BUCKET, Key=item['photo_location'])

    expression = "SET username = :username, bio = :bio, quill_bio = :quill_bio, page_location = :page_location"
    values = {":username":username, ":bio":userbio, ":quill_bio":quill_bio, ":page_location":s3_path}
    if userimgname:
        expression += ", photo_location = :img_path"
        values[":img_path"] = userimgname

    table.update_item(Key={'author_email': userid},
               UpdateExpression=expression,
               ExpressionAttributeValues=values)

    return build_static_html_profile(userid, s3_path)


def build_static_html_profile(userid, page_s3_path):
    """
    This is a helper function that builds an html page for each author using their profile information from DynamoDB.
    If you'd like to learn a little more about DynamoDB, you can check out the "DynamoDB" chapter in the Serverless Flask guide at compellingpython.com
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(DYNAMO_USER_TABLE)
    item = table.get_item(Key={'author_email': userid})

    username = item['Item']['username']
    bio = item['Item']['bio']
    photo_location = item['Item']['photo_location']

    page = render_template('static_author_page.html', item=item['Item'])
    pagefile = BytesIO(bytes(page, 'utf-8'))

    s3 = boto3.client('s3')

    s3.upload_fileobj(pagefile, BUCKET, page_s3_path, ExtraArgs={'ContentType': 'text/html'})

    return "http://compellingsciencefiction.com/{}".format(page_s3_path)

class User(UserMixin):
    """
    This user template builds objects that make accessing databased user information easier from the rest of the application.
    It inherits several properties and methods from "UserMixin" for use with 
    """
    def __init__(self, userid, username=None):
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(DYNAMO_USER_TABLE)
        self.id = userid
        self.confirmed = False
        self.publisher_confirmed = False
        if username:
            self.username = username
        else:
            item = self.table.get_item(Key={'author_email': userid})
            self.username = item['Item']['username']
            self.password_hash = item['Item']['password_hash']
            self.confirmed = item['Item']['email_confirmed']
            self.publisher_confirmed = item['Item']['csf_approved']
            if 'quill_bio' in item['Item']:
                self.quill_bio = item['Item']['quill_bio']
            else:
                self.quill_bio = ""

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        
        self.table.update_item(Key={'author_email': self.id},
               UpdateExpression="SET email_confirmed = :email_confirmed",
               ExpressionAttributeValues={":email_confirmed":True})

        return True

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')


    def email(self, template, subject, **kwargs):
        emailclient = boto3.client("ses")

        msg_body = render_template(template+".txt", **kwargs)

        # TODO: harden
        response = emailclient.send_email(
            Source='joe@compellingsciencefiction.com',
            Destination={
                'ToAddresses': [
                    self.id,
                ],
            },
                Message={
                    'Subject': {
                        'Data': subject,
                        'Charset': "UTF-8"
                    },
                    'Body': {
                        'Text': {
                            'Data': msg_body,
                            'Charset': "UTF-8"
                        }
                    }
                }
        )