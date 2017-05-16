# imports for this project
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# using a secret key for password hashing
secret = 'pizzalove'

# hashing password stuff
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# Creating a user model that keeps track of all the users registered
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Creating a like model which keeps track of the person who liked the post and post id
class Like(db.Model):
    uname = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)

# This deals with like realted stuff
class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name == post.user_name:
            self.write("You can not like your own post")
            return

        else:
            uname = self.user.name
            post_id = int(post.key().id())
            check_like = Like.all().filter('uname =',
                                           uname).filter('post_id =',
                                                         post_id).get()

            if check_like:
                self.write("You'have already liked this post, sorry")
                return

            else:
                like = Like(parent=key,
                            uname=self.user.name,
                            post_id=int(post_id))

                post.like_count += 1
                like.put()
                post.put()
                self.redirect('/?')

# Creating a comment model that keeps track of content of comment, name of the person who commented and post id
class Comment(db.Model):
    content = db.StringProperty(required=True)
    user_name = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)

# This deals with comment related stuff
class CommentFront(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
            return

        if not post:
            self.error(404)
            return
        else:
            self.render("comment.html", post=post, user_name=self.user.name)

    def post(self, post_id):
        content = self.request.get('content')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        abc = Comment(parent=key, content=content,
                      user_name=self.user.name, post_id=int(post_id))
        abc.put()
        post.comment_count += 1
        post.put()
        comment = greetings = Comment.all().filter('post_id =', int(post_id))
        self.redirect("/")

# This deals with deleting the comment
class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)
        ckey = db.Key.from_path('Comment', int(comment_id), parent=key)
        c = db.get(ckey)
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name == c.user_name:
            self.render("deletecomment.html")
        elif self.user:
            self.write("Sorry, you can delete your own posts only")
            return

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        ckey = db.Key.from_path('Comment', int(comment_id), parent=key)
        c = db.get(ckey)
        c.delete()
        self.redirect("/")

# This deals with editing the comment
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        ckey = db.Key.from_path('Comment', int(comment_id), parent=key)
        c = db.get(ckey)
        self.render("editComment.html", content=c.content)

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)
        ckey = db.Key.from_path('Comment', int(comment_id), parent=key)
        c = db.get(ckey)
        content = self.request.get('content')
        if content and self.user.name == p.user_name:
            c.content = content
            c.put()
        else:
            self.write("OOPS!! you have permissions\
                        to edit your own comments only")


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Creating a post model that keeps track of all post related information
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    like_count = db.IntegerProperty(default=0)
    user_name = db.StringProperty(str)
    comment_count = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

# This is the page that renders posts
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        if self.user:
            self.render('front.html', posts=posts, uname=self.user.name)
        else:
            self.render('frontp.html', posts=posts)

# This is the page where blog related information can be viewed
class ViewBlog(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        post_id = int(post.key().id())
        comment = greetings = Comment.all().filter('post_id =', post_id)
        if not post:
            self.error(404)
        if not self.user:
            self.redirect("/login")
        else:
            self.render("permalink.html", post=post,
                        comment=comment, uname=self.user.name)

# It deals with posting the blog
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

# Adding a new post 
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, user_name=self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)

# Deleting existing post
class deltePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name == post.user_name:
            self.render("deletepost.html")
        elif self.user:
            self.write("Sorry, you can delete your own posts only")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user.name != post.user_name:
            return self.redirect('/')
        post.delete()
        return self.redirect('/')

# editing existing post
class editPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name == post.user_name:
            self.render("editpost.html", post=post)
        elif self.user:
            self.write("you can edit your own posts only")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user.name != post.user_name:
            self.redirect('/')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
#           p = Post(parent = blog_key(), subject = subject,
#           content = content, user_name = self.user.name)
#           p.put()
            post.put()
            self.redirect('/')
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Signup related validation
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# registering the user
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

# login related validation
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

# logout related validation
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([
                               ('/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/delete/([0-9]+)', deltePost),
                               ('/blog/edit/([0-9]+)', editPost),
                               ('/blog/comment/([0-9]+)', CommentFront),
                               ('/blog/view/([0-9]+)', ViewBlog),
                               ('/like/([0-9]+)', LikePost),
                               ('/blog/comment/delete/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/comment/edit/([0-9]+)/([0-9]+)',
                                EditComment)
                               ],
                              debug=True)
