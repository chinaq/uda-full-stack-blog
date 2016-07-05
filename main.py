#coding=utf-8

#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import random
import hashlib
import hmac
import logging
import time
import jinja2
from string import letters
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
	autoescape=True)

secret = 'itsveryverysecret'


# user
def users_key(group = 'default'):
	return db.Key.from_path('users', group)
	
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())



# blog
class Blog(db.Model):
	title = db.StringProperty(required = True)
	body = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	owner = db.StringProperty()
	liked = db.IntegerProperty()

# comment
class Comment(db.Model):
	blog_id = db.StringProperty() 
	blog_title = db.StringProperty()
	body = db.StringProperty()
	user_name = db.StringProperty()
	

class Like(db.Model):
	blog_id = db.StringProperty() 
	user_name = db.StringProperty()






# Handlers --------------------------------------------------------------------------------

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(**params)

	def render(self, template, **kw):
		kw['is_login'] = self.user
		self.write(self.render_str(template, **kw))

	def make_secure_val(self, val):
		return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
		
	def check_secure_val(self, secure_val):
		val = secure_val.split('|')[0]
		if secure_val == self.make_secure_val(val):
			return val
			
	def set_secure_cookie(self, name, val):
		cookie_val = self.make_secure_val(val)
		# logging.info('********************set_secure_cookie*************************************')
		# logging.info('cookie_val: ' + cookie_val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))
			
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and self.check_secure_val(cookie_val)
		
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))
		
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		# logging.info('********************initialize*************************************')
		# logging.info('uid: ' + uid)
		self.user = uid and User.by_id(int(uid))
		
		
		
		
# show all posts
class MainHandler(Handler):
	def render_blogs(self):
		blogs = db.GqlQuery("SELECT * FROM Blog "
							"ORDER BY created DESC")
		self.render("index.html", blogs=blogs)

	def get(self):
		self.render_blogs()


# new post
class NewPostHandler(Handler):
	def render_newpost(self, title="", body="", error=""):
		self.render("newpost.html", title=title, body=body, error=error)

	def get(self):
		if self.user:
			self.render_newpost()
		else:
			self.redirect("/login")
			

	def post(self):
		if not self.user:
			return self.redirect("/login")

		title = self.request.get("subject")
		body = self.request.get("content")
		if self.user and title and body:
			b = Blog(title = title, body = body, owner=self.user.name, liked=0)
			b_key = b.put()		
			self.redirect("/%d" %b_key.id())
		else:
			error = "we need both a title and a body!"
			self.render_newpost(title, body, error)


# edit post
class EditHandler(Handler):
	def render_edit(self, blog_id, error=""):
		b = Blog.get_by_id(int(blog_id))
		self.render("edit.html", title=b.title, body=b.body, id=blog_id, error=error)

	def get(self, blog_id):
		if (not self.user):
			return self.redirect("/login");

		b = Blog.get_by_id(int(blog_id))
		error=""
		if (not b) or (self.user.name != b.owner):
			error = "you can not edit."
		self.render_edit(blog_id, error)
		
	def post(self, blog_id):
		if (not self.user):
			return self.redirect("/login");
	
		body = self.request.get("body")
		if id and body:
			b = Blog.get_by_id(int(blog_id))
			if b and b.owner == self.user.name:
				b.body=body
				b.put()
				self.redirect("/%d" %b.key().id())
			else:
				error = "an error id!"
				self.render_edit(blog_id, error)
		else:
			error = "we need both a id and a body!"
			self.render_edit(blog_id, error)



# delete post
class DeleteHandler(Handler):

	def post(self):
		if (not self.user):
			return self.redirect("/login");
		
		id = self.request.get("id")
		b = Blog.get_by_id(int(id))

		result =""
		if b and b.owner == self.user.name:
			db.delete(b)
			result = "The post is deleted."
		else:
			result = "You can not delete it."
		self.render("delete.html", result=result)



# like post
class LikeHandler(Handler):

	def post(self):
		if (not self.user):
			return self.redirect("/login");
		
		result = ""
		id = self.request.get("id")
		b = Blog.get_by_id(int(id))
		if b.owner == self.user.name:
			result = "You can not like youself."
		elif Like.all().filter("blog_id =", id).filter("user_name =", self.user.name).get():
			result = "You have already liked it."
		else:
			Like(blog_id=id, user_name=self.user.name).put()
			b.liked += 1
			b.put()
			result = "You successfully liked it."
		self.render("like.html", result=result)


# add new comment
class NewCommentHandler(Handler):
	def render_newcomment(self, blog_title="", error=""):
		self.render("newcomment.html", blog_title=blog_title, error=error)

	def get(self, blog_id):
		if not self.user:
			return self.redirect("/login")
		
		error=""
		blog_title=""
		blog = Blog.get_by_id(int(blog_id))
		if not blog:
			error = "can not find the post."
		else:
			blog_title = blog.title
		return self.render_newcomment(blog_title=blog_title, error=error)
			
			

	def post(self, blog_id):
		if not self.user:
			return self.redirect("/login")

		body = self.request.get("body")
		error=""
		blog_title=""
		blog = Blog.get_by_id(int(blog_id))
		if not blog:
			error = "can not find the post."
			return self.render_newcomment(blog_title=blog_title, error=error)
		else:
			Comment(blog_id=blog_id, blog_title=blog.title, user_name=self.user.name, body=body).put()
			time.sleep(0.1)
			return self.redirect("/" + blog_id)


# edit comment
class EditCommentHandler(Handler):
	def render_editcomment(self, blog_title, comment_id, commnet_body, error=""):
		b = Comment.get_by_id(int(comment_id))
		self.render("editcomment.html", blog_title=blog_title, comment_id=comment_id, comment_body=commnet_body, error=error)

	def get(self, comment_id):
		if (not self.user):
			return self.redirect("/login");

		comment = Comment.get_by_id(int(comment_id))
		error=""
		if (not comment) or (self.user.name != comment.user_name):
			error = "you can not edit."
		self.render_editcomment(comment.blog_title, comment_id, comment.body, error)
		

	def post(self, comment_id):
		if (not self.user):
			return self.redirect("/login");
	
		comment_body = self.request.get("comment_body")
		if comment_id and comment_body:
			comment = Comment.get_by_id(int(comment_id))
			if comment and comment.user_name == self.user.name:
				comment.body=comment_body
				comment.put()
				self.redirect("/%d" %int(comment.blog_id))
			else:
				error = "an error id!"
				self.render_editcomment(comment_id, error)
		else:
			error = "we need both a id and a body!"
			self.render_editcomment(comment_id, error)





# delete post
class DeleteCommentHandler(Handler):

	def post(self):
		if (not self.user):
			return self.redirect("/login");
		
		id = self.request.get("comment_id")
		comment = Comment.get_by_id(int(id))

		result =""
		if comment and comment.user_name == self.user.name:
			db.delete(comment)
			result = "The comment is deleted."
		else:
			result = "You can not delete it."
		self.render("delete.html", result=result)





# show oneblog post
class OneBlogHandler(Handler):
	def render_oneblog(self, blog_id):
		b = Blog.get_by_id(int(blog_id))
		comments = Comment.all().filter("blog_id =", blog_id)
		can_edit = False

		# logging.info('********************can_edit*************************************')
		# logging.info('self.user.name: ' + self.user.name)
		# logging.info('blog.owner: ' + b.owner)
		
		if self.user and b and self.user.name == b.owner:
			can_edit = True
		self.render("oneblog.html", title=b.title, body=b.body, id=blog_id, owner=b.owner, \
									can_edit=can_edit, liked=b.liked, comments=comments)

	def get(self, blog_id):
		self.render_oneblog(blog_id)





# users hanlders ------------------------------------------------------------------------------


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


# regist
class SignupHandler(Handler):
	def get(self):
		self.render("signup.html", signError=SignError())

	def post(self):
		isNoError = True

		signinfo = SignInfo()
		signinfo.username = self.request.get("username")
		signinfo.password = self.request.get("password")
		signinfo.verify = self.request.get("verify")
		signinfo.email = self.request.get("email")
		
		signerror = SignError()
		if not signinfo.username:
			signerror.username_error = "username can not null"
			isNoError = False
		if not signinfo.password:
			signerror.password_error = "password can not null"
			isNoError = False
		if not signinfo.password == signinfo.verify:
			signerror.verify_error = "two passwords not match"
			isNoError = False
		existed = User.all().filter("name =", signinfo.username).get()
		if existed:
			signerror.username_error = "username has existed"
			isNoError = False			

		if isNoError:				
			pw_hash = make_pw_hash(signinfo.username, signinfo.password)
			user = User(name=signinfo.username, pw_hash=pw_hash, email=signinfo.email, parent = users_key())
			user.put()
			self.login(user)
			self.redirect("/welcome")
		else:
			self.render("signup.html", signError=signerror)			


class SignInfo():
	username=""
	password=""
	verify=""
	email=""


class SignError():
	username_error=""
	password_error=""
	verify_error=""


class WelcomeHandler(Handler):
	def get(self):
		# username = str(self.request.cookies.get("username"))

		if self.user:
			username = self.user.name
			self.render("welcome.html", username=username)
		else:
			# self.redirect("/signup")
			self.write("no user loggin")


class LoginHandler(Handler):
	def get(self):
		self.render("login.html", error="")

	def post(self):
		input_username = self.request.get("username")
		input_password = self.request.get("password")
		user = User.all().filter('name =', input_username).get()
		if not user:
			return self.render("login.html", error="error username")
		
		# logging.info('********************login*************************************')
		# logging.info('user.name: ' + user.name)
		# logging.info('user.key: ' + str(user.key()))
		# logging.info('user.key.id: ' + str(user.key().id()))

		salt = user.pw_hash.split(',')[0]
		pw_hash = make_pw_hash(user.name, input_password, salt)
		if pw_hash != user.pw_hash:
			return self.render("login.html", error="error password")

		self.login(user)
		self.redirect("/welcome")



class LogoutHandler(Handler):
	def get(self):
		self.logout()			
		self.redirect("/login")
			

class TestHandler(Handler):
	def render_base(self):
		self.render("test.html")

	def get(self):
		self.render_base()	


app = webapp2.WSGIApplication([
	('/test', TestHandler),
    ('/', MainHandler),
    ('/newpost', NewPostHandler),
	('/edit/(\d+)', EditHandler),
	('/delete', DeleteHandler),
	('/like', LikeHandler),
	('/newcomment/(\d+)', NewCommentHandler),
	('/editcomment/(\d+)', EditCommentHandler),
	('/deletecomment', DeleteCommentHandler),
    ('/(\d+)', OneBlogHandler),
    ('/signup', SignupHandler), 
    ('/welcome',WelcomeHandler ),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler)
], debug=True)
