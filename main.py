from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
import hashlib, random, string, datetime

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://blogz:blogzland@localhost:8889/blogz'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = 'hunterdragoniswaycool'


class Blog(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    entry = db.Column(db.String(120))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email = db.Column(db.String(120))

    def __init__(self, name, entry, owner_id, email):
        self.name = name
        self.entry = entry
        self.owner_id = owner_id
        self.email = email

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(120))
    blogs = db.relationship('Blog', backref='owner')

    def __init__(self, email, password):
        self.email = email
        self.password = password
        
        
def make_salt():
    sal = ""
    for elem in range(5):
        num1 = random.randrange(9)
        num2 = str(num1)
        sal += num2
    return sal
    
def make_pw_hash(password):
    hash = hashlib.sha256(str.encode(password)).hexdigest()
    return hash

def check_pw_hash(password, hash):
    hash2 = hash[5:]
    if make_pw_hash(password) == hash2:
        return True
    else:
        return False


@app.before_request
def require_login():
    allowed_routes = ['login', 'signup', 'index', 'blog']
    if request.endpoint not in allowed_routes and 'email' not in session:
        return redirect('/login')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_pw_hash(password, user.password):
            session['email'] = email
            flash("Logged in")
            return redirect('/newpost')
        elif not user:
            flash("User does not exist")
            return redirect('signup')
        else:
            flash('User password incorrect')

    return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        
        password = request.form['password']
        verify = request.form['verify']
        if not email or not password or not verify:
            flash("Please fill in all form spaces")
            return redirect('/signup')
        if password != verify:
            flash("Password and Password Verify fields do not match")
            return redirect('/signup')
        existing_user = User.query.filter_by(email=email,).first()
        if not existing_user:
            salt = make_salt()
            hash = make_pw_hash(password)
            password = salt + hash
            new_user = User(email, password)
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email
            
            flash("Signed In")
            return redirect('/newpost')
        else:
            flash('Duplicate User')
            return redirect('/signup')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    del session['email']
    return redirect('/blog')

@app.route('/Blog', methods=['GET', 'POST'])
def blog():
    entry = request.args.get('id')
    allentries = Blog.query.all()
    blogger_id = request.args.get('owner_id')
    if entry:
        indv_post = Blog.query.get(entry)
        return render_template('entry.html', entry=indv_post)
    if blogger_id:
        posts = Blog.query.filter_by(owner_id=blogger_id) 
        return render_template('blogger.html',entries=posts) 
    
    return render_template('Blog.html', entries=allentries)

@app.route('/', methods=['POST', 'GET'])
def index():
    allusers = User.query.all()
    return render_template('index.html', users = allusers)

@app.route('/newpost', methods=['POST', 'GET'])
def newpost():
    if request.method == 'POST':
        errorname = ""
        errorentry = ""
        name = request.form['name']
        if not name:
            errorname = "Please submit a name for the post"
        entry = request.form['entry']
        owner = User.query.filter_by(email=session['email']).first()
        owner_id = owner.id
        email = owner.email
        if not entry:
            errorentry = "Please submit and entry for the post"
        if errorname or errorentry:
            return render_template('newpost.html', errorname = errorname, errorentry = errorentry)
        else:
            new_entry = Blog(name, entry, owner_id, email)
            db.session.add(new_entry)
            db.session.commit()
            user = User.query.filter_by(id = owner_id).first()
            email = user.email
            return render_template('entry2.html', name=name, entry=entry, new_entry=new_entry, email=email)

    return render_template('newpost.html', errorname = "", errorentry = "")

        







if __name__ == '__main__':
    app.run()