import os
import re
import random
import hashlib
import hmac
import logging
import cgi
import urllib
import json
import datetime
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

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
        # populate users
        
        # populate groups
        # populate group-user membership.

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class Group(db.Model):
    email = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    
    @classmethod
    def by_id(cls, gid):
        return Group.get_by_id(gid)

    @classmethod
    def by_name(cls, name):
        g = Group.all().filter('email =', name).get()
        return g
    
    @classmethod
    def register(cls, email, pw):
        pw_hash = make_pw_hash(email, pw)
        return Group(pw_hash = pw_hash,
                    email = email)
    
    @classmethod
    def login(cls, email, pw):
        g = cls.by_name(email)
        if g and valid_pw(email, pw, g.pw_hash):
            return g
        
class User(db.Model):
    email = db.EmailProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    join_date = db.DateTimeProperty(auto_now_add = True)
    groups = db.TextProperty(tuple)
    
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
#        selectedUser = db.GqlQuery("select * from User where email = '" + name + "'")
#        return selectedUser[0]
        u = User.all().filter('email =', name).get()
        return u

    @classmethod
    def register(cls, email, pw):
        pw_hash = make_pw_hash(email, pw)
        return User(parent = users_key(),
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, email, pw):
        u = cls.by_name(email)
        if u and valid_pw(email, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


# form relationship with entity Group and User.
class GroupPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    fromadd = db.StringProperty(required = True, indexed = True)    # user id.
    toadd = db.StringProperty(required = True, indexed = True)      # groupid
    read = db.BooleanProperty(required = True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    fromadd = db.StringProperty(required = True, indexed = True)
    toadd = db.StringProperty(required = True, indexed = True)
    read = db.BooleanProperty(required = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        logging.warning("username is: " + str(self.user))
        username = self.user.email
        if username:
            sumqueries = []
            posts = db.GqlQuery("select * from Post where toadd = '" + username + "'")
            # find the groups user is a member of.
            sumGroupPosts = []
            listOfGroups = json.loads(self.user.groups)
    #        logging.warn("listofgroups: " + listOfGroups)
            for member in listOfGroups:
                # show messages for the groups of which he is member of right now.
                logging.warn("member: " + str(member))
                end = member['end']
                if end is None:
                    group = Group.get_by_id(member['group_id'])
                    if group:
                        logging.warn("group found!")
                        groupposts = db.GqlQuery("select * from GroupPost where toadd = '" + group.email + "'")
                        for q in groupposts:
                            sumGroupPosts.append(q)
                elif (member['end'] > datetime.datetime.today().isoformat()):
                    group = Group.get_by_id(member['group_id'])
                    if group:
                        logging.warn("group found!")
                        groupposts = db.GqlQuery("select * from GroupPost where toadd = '" + group.email + "'")
                        for q in groupposts:
                            sumGroupPosts.append(q)
            
            for q in posts:
                sumqueries.append(q)
            for q in sumGroupPosts:
                sumqueries.append(q)
            self.render('front.html', posts = sumqueries)
        else:
            self.render('front.html', posts = undefined)

class PostPage(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        
        post.read = True
        post.put()
        
        self.render("permalink.html", post = post)
        
    def get(self, post_id):
        #do nothing
        self.post(post_id)
        
class GroupPostPage(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('GroupPost', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        
        post.read = True
        post.put()
        
        self.render("permalink.html", post = post)
        
    def get(self, post_id):
        #do nothing
        self.post(post_id)
        
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            # get contact list for the user.
            contactList = db.GqlQuery("select toadd from Post where fromadd = '" + self.user.email + "'")
        #    contactList = map(lambda x: x[1], queryresult)
            self.render("newpost.html", availableTags = urllib.urlencode({"" : ['anupam@pally.in','mediratta@gmail.com']}))
        #    self.render("newpost.html", availableTags = json.dumps(['anupam@pally.in','mediratta@gmail.com']))
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        toadd = self.request.get('toadd')
        fromadd = self.user.email
        isgroup = self.request.get('isgroup')

        if subject and content and fromadd and toadd:
            if isgroup == 'yes':
                p = GroupPost(parent = blog_key(), subject = subject, content = content, fromadd = fromadd, toadd = toadd, read = False)
                p.put()
                self.redirect('/blog/group/%s' % str(p.key().id()))
            else: 
                p = Post(parent = blog_key(), subject = subject, content = content, fromadd = fromadd, toadd = toadd, read = False)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username
#    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.isgroup = self.request.get('isgroup')

        params = dict(email = self.email)

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

class Register(Signup):
    def done(self):
        if self.isgroup:
            g = Group.by_name(self.email)
            if g:
                msg = 'That group already exists.'
                self.render('signup-form.html', error_username = msg)
            else:
                g = Group.register(self.email, self.password)
                g.put()
                self.login(g)
                self.redirect('/blog')
        else:    
            #make sure the user doesn't already exist
            u = User.by_name(self.email)
            if u:
                msg = 'That user already exists.'
                self.render('signup-form.html', error_username = msg)
            else:
                u = User.register(self.email, self.password)
                u.groups = json.dumps([])
                u.put()
                self.login(u)
                self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        groupAll = self.request.get('groupall')
        logging.warn("group all: " + groupAll)
        u = User.login(username, password)
        if u:
            self.login(u)
            # use groupall information.
            if groupAll == 'yes':
                # add the user to all the groups if not there.
                # find gid of all groups.
                groupMembershipList = []
                allgroups = db.GqlQuery("select * from Group")
                for ind in allgroups:
                    groupMembershipList.append({'user_id': u.key().id_or_name(), 'group_id': ind.key().id_or_name(), 'start':       str(datetime.datetime.today()), 'end': None})
                u.groups = json.dumps(groupMembershipList)
            elif groupAll == "no":
                # add the end date for all the groups.
                newgroups = []
                if u.groups:
                    unload = json.loads(u.groups)
                    for ind in unload:
                        groupid = ind['group_id']
                        start = ind['start']
                        newgroups.append({'user_id': u.key().id_or_name(), 
                                          'group_id': groupid, 
                                          'start': start, 
                                          'end': str(datetime.datetime.today())
                                          })
                    u.groups = json.dumps(newgroups)
            logging.warn("after updating u.groups: " + str(u.groups))
            u.put()
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/group/([0-9]+)', GroupPostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
