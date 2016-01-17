import os
import re
from string import letters
import jinja2
import webapp2
import hashlib
import hmac
import json
from urllib2 import URLError
from datetime import datetime, timedelta
from google.appengine.api import memcache
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

def render_post(response, blog):
	response.out.write('<b>' + blog.subject + '</b><br>')
	response.out.write(blog.content)

class MainPage(Handler):
  def get(self):
	  self.render("first.html")

#Blog Stuff

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Blog(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

QUERIED = re.compile("(?i)Queried\s+(\d+)(\.\d+)?\s+seconds?\s+ago")

def age_set(key, val):
	save_time = datetime.utcnow()
	memcache.set(key, (val, save_time))

def age_get(key):
	r = memcache.get(key)
	if r:
		val, save_time = r
		age = (datetime.utcnow() - save_time).total_seconds()
	else:
		val, age = None,0

	return val,age

def add_blog(blog):
	blog.put()
	top_blogs(update = True)
	return str(post.key().id())

def top_blogs(update = False):
	mc_key = 'BLOGS'
	blogs, age = age_get(mc_key)
	if blogs is None or update:
		q = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
		blogs = list(q)
		age_set(mc_key,blogs)

	return blogs,age

def age_str(age):
	s = 'queried %s seconds ago'
	age = int(age)
	if age==1:
		s = s.replace('seconds', 'second')
	return s % age


class BlogHandler(Handler):
	def render_front(self, subject="", content="", created=""):
		blogs, age = top_blogs()
		self.render("blogs.html", subject=subject, content=content, blogs=blogs, created=created, age= age_str(age))

	def get(self):
		self.render_front()

class BJsonHand(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		time_fmt = '%c'
		blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
		biglist = []
		smalldict = {}
		for b in blogs:
			smalldict = {"content": b.content, "subject": b.subject, "created": b.created.strftime(time_fmt)}
			biglist.append(smalldict)
		json_txt = json.dumps(biglist)
		self.write(json_txt)

class OJsonHand(Handler):
	def get(self, blog_id):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		time_fmt = '%c'
		rblog = Blog.get_by_id(int(blog_id))
		smalldict = {"content": rblog.content, "subject": rblog.subject, "created": rblog.created.strftime(time_fmt)}
		json_txt = json.dumps(smalldict)
		self.write(json_txt)


class NewPost(Handler):
	def render_front(self, subject="", content="", error=""):
		self.render("newpost.html",subject=subject, content=content, error=error)

	def get(self):
		self.render_front()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		if content and subject:
			b = Blog(subject=subject, content=content)
			b.put()
			#self.write(b.key().id())
			self.redirect('/blog/%s' %str(b.key().id()))
		else:
			error = "We need both the title and the blog!"
			self.render_front(subject = subject, content=content, error = error)


class CreatedPost(Handler):
	def get(self, blog_id):
		#self.write(blog_id)
		blog_key = 'BLOG_' + blog_id

		rblog, age = age_get(blog_key)
		if not rblog:
			rblog = Blog.get_by_id(int(blog_id))
			age_set(blog_key, rblog)
			age = 0
		if not rblog:
			self.error(404)
			return
		self.render("permalink.html",subject = rblog.subject, content = rblog.content, created= rblog.created, age = age_str(age))

class Flush(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')

# ROT-13
class Rot13(Handler):
	def get(self):
		self.render('rot13-form.html')

	def post(self):
		rot13 = ''
		text = self.request.get('text')
		if text:
			rot13 = text.encode('rot13')

		self.render('rot13-form.html', text = rot13)

#Sign up Page

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

SECRET = 'howaboutno'

def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
	if h:
		val = h.split('|')[0]
		if h == make_secure_val(val):
			return val

class Signup(Handler):

	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username = username,
					  email = email)

		users = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")

		for u in users:
			if u.username == username and u.password == password:
				params['error_username'] = "That user is already registered."
				have_error = True
				break

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That's not a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			u = User(username=username,password=password,email=email)
			u.put()
			secured_cookie = make_secure_val(str(u.key().id()))
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % secured_cookie)
			self.redirect('/blog/welcome')

#Welcome page
class Login(Handler):
	def render_front(self, username="", error_login=""):
		self.render("login-form.html",username=username, error_login=error_login)

	def get(self):
		self.render("login-form.html")

	def post(self):
		users = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")
		msg = 'Invalid Login'
		have_error = True
		username = self.request.get('username')
		password = self.request.get('password')
		for u in users:
			if u.username==username and u.password==password:
				have_error = False
				msg=''
				break

		if have_error:
			self.render_front(username = username, error_login = msg)
		else:
			self.redirect('/blog/welcome')

class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect('/blog/signup')


class Welcome(Handler):
	def get(self):
		cookie_str = self.request.cookies.get('user_id')
		useridprcd = check_secure_val(cookie_str)
		if useridprcd:
			ruser = User.get_by_id(int(useridprcd))
			self.render('welcome.html', username = ruser.username)
		else:
			self.redirect('/blog/signup')






app = webapp2.WSGIApplication([
	('/blog', BlogHandler),
	('/blog/.json', BJsonHand),
	('/blog.json', BJsonHand),
	('/blog/newpost', NewPost),
	('/blog/([0-9]+)', CreatedPost),
	('/blog/([0-9]+).json', OJsonHand),
	('/', MainPage),
	('/rot13', Rot13),
	('/blog/signup', Signup),
	('/blog/welcome', Welcome),
	('/blog/login', Login),
	('/blog/logout', Logout),
	('/blog/flush', Flush)
], debug=True)
