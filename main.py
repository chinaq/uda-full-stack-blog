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
import jinja2
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
	autoescape=True)



# blog
class Blog(db.Model):
	title = db.StringProperty(required = True)
	body = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

# comment
class Comment(db.Model):
	blog = db.ReferenceProperty(Blog) 
	body = db.TextProperty()
	
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()




# Handlers --------------------------------------------------------------------------------

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(**params)

	def render(self, template, **kw):
		kw['is_login'] = self.user = str(self.request.cookies.get("username"))
		self.write(self.render_str(template, **kw))



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
		self.render_newpost()

	def post(self):
		title = self.request.get("subject")
		body = self.request.get("content")
		if title and body:
			b = Blog(title = title, body = body)
			b_key = b.put()		
			self.redirect("/%d" %b_key.id())
		else:
			error = "we need both a title and a body!"
			self.render_newpost(title, body, error)


# show newest post
class EditHandler(Handler):
	def render_edit(self, blog_id, error=""):
		b = Blog.get_by_id(int(blog_id))
		self.render("edit.html", title=b.title, body=b.body, id=blog_id)

	def get(self, blog_id):
		self.render_edit(blog_id)
		
	def post(self, blog_id):
		# id = self.request.get("id")
		body = self.request.get("body")
		if id and body:
			b = Blog.get_by_id(int(blog_id))
			if b:
				b.body=body
				b.put()
				self.redirect("/%d" %b.key().id())
			else:
				error = "an error id!"
				self.render_edit(blog_id, error)
		else:
			error = "we need both a id and a body!"
			self.render_edit(blog_id, error)


# show newest post
class OneBlogHandler(Handler):
	def render_oneblog(self, blog_id):
		b = Blog.get_by_id(int(blog_id))
		self.render("oneblog.html", title=b.title, body=b.body, id=blog_id)

	def get(self, blog_id):
		self.render_oneblog(blog_id)





# users hanlders ------------------------------------------------------------------------------

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

		if isNoError:			
			self.response.headers.add_header("Set-Cookie", str("username=%s; Path=/" % signinfo.username))
			self.response.headers.add_header("Set-Cookie", str("password=%s; Path=/" % signinfo.password))			
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
		username = str(self.request.cookies.get("username"))
		if username:
			self.render("welcome.html", username=username)
		else:
			self.redirect("/signup")


class LoginHandler(Handler):
	def get(self):
		self.render("login.html", error="")

	def post(self):
		cookie_username = str(self.request.cookies.get("username"))
		cookie_password = str(self.request.cookies.get("password"))
		input_username = self.request.get("username")
		input_password = self.request.get("password")

		if cookie_password == input_password and cookie_username == input_username:
			self.redirect("/welcome")
		else:
			self.render("login.html", error="error username or error password")


class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header("Set-Cookie", str("username=; Path=/"))
		self.response.headers.add_header("Set-Cookie", str("password=; Path=/"))			
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
    ('/(\d+)', OneBlogHandler),
    ('/signup', SignupHandler), 
    ('/welcome',WelcomeHandler ),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler)
], debug=True)
