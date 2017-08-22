#!/usr/bin/env python
#
# Copyright 2016 Google Inc.
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
import os
import hashlib
import json
import random
import string
import jinja2
import webapp2
import re
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))

config_filname = os.path.join(os.path.dirname(__file__), "config.json")
with open(config_filname) as config_file:
    config = json.load(config_file)

secret_key = config["secret"]


class Handler(webapp2.RequestHandler):
    """Handler for all web requests"""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def hash_str(self, s):
        """Hashes a string concatenated with secret in config.json"""

        return hashlib.sha256("{0}{1}".format(s, secret_key)).hexdigest()

    def make_salt(self):
        return "".join(random.choice(string.letters) for x in xrange(10))

    def make_pw_hash(self, email, pw, salt=None):
        """Create a hashed password from email, password, and salt"""

        if not salt:
            salt = self.make_salt()
        hash = self.hash_str("{0}{1}{2}".format(email, pw, salt))
        return "{0}|{1}".format(hash, salt)

    def valid_pw(self, email, pw, hash):
        """Verify a password is valid"""

        salt = hash.split("|")[1]
        return hash == self.make_pw_hash(email, pw, salt)

    def set_cookie(self, name, val, path, secure):
        """Set both secure and insecure cookies"""

        if secure:
            cookie_val = "{0}|{1}".format(self.hash_str(val), val)
        else:
            cookie_val = val
        self.response.headers.add_header(
            "Set-cookie",
            "{0}={1}; Path={2}".format(name, cookie_val, path)
        )

    def read_cookie(self, name, secure):
        """Read both secure and insecure cookies"""

        cookie_val = self.request.cookies.get(name)
        if cookie_val and secure:
            return cookie_val.split("|")[1]
        else:
            return cookie_val

    def valid_cookie(self, cookie_val):
        """Verify a secure cookie is valid"""

        val = cookie_val.split("|")[1]
        return cookie_val == "{0}|{1}".format(self.hash_str(val), val)

    def user_post(self, uid, pid):
        """Verify a post was created by a particular user"""

        user = User.get_by_id(int(uid))
        user_posts = db.GqlQuery(
            "SELECT * FROM Post WHERE author = '{0}'".format(user.name)
        )
        for user_post in user_posts:
            if user_post.key().id() == int(pid):
                return True
        return False

    def user_comment(self, uid, cid):
        """Verify a comment was created by a particular user"""

        user = User.get_by_id(int(uid))
        user_comments = db.GqlQuery(
            "SELECT * FROM Comment WHERE author = '{0}'".format(user.name)
        )
        for user_comment in user_comments:
            if user_comment.key().id() == int(cid):
                return True
        return False

    def valid_user(self):
        """Verify that the current user is logged in as a valid user"""

        user_cookie = self.request.cookies.get("user")
        if not user_cookie:
            return False
        if not self.valid_cookie(user_cookie):
            return False
        uid = self.read_cookie("user", True)
        if len(uid) == 0:
            return False
        return True


class Post(db.Model):
    """Database model for posts"""

    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created_time = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)


class Comment(db.Model):
    """Database model for comments"""

    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created_time = db.DateTimeProperty(auto_now_add=True)
    post_id = db.IntegerProperty(required=True)


class User(db.Model):
    """Database model for users"""

    email = db.EmailProperty(required=True)
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)
    liked_posts = db.ListProperty(int, default=None)

    @classmethod
    def get_by_email(cls, email):
        return User.all().filter("email =", email).get()


class MainPage(Handler):
    """Handler for the landing and front pages"""

    def get(self):
        uid = self.read_cookie("user", True)
        if uid:
            # Check that user is valid
            if not self.valid_user():
                self.set_cookie("user", "", "/", False)
                self.redirect("/")
            else:
                user = User.get_by_id(int(uid))
                posts = db.GqlQuery(
                    "SELECT * FROM Post ORDER BY created_time DESC"
                )
                self.render("index.html", user=user, posts=posts)
        else:
            self.render("landing.html")


class SignUpPage(Handler):
    """Handler for the sign up page"""

    def get(self):
        self.render("signup.html", error=None)

    def post(self, error=None):
        email = self.request.get("email")
        name = self.request.get("name")
        password = self.request.get("password")
        confirm = self.request.get("confirm-password")
        salt = self.make_salt()

        # Ensure all required fields have been submitted
        if len(email) == 0 or len(password) == 0 or len(confirm) == 0:
            error = "Missing one or more required fields."
        # Ensure the password and confirm password fields match
        elif password != confirm:
            error = "Your passwords do not match."
        # Ensure the email is in a valid email format
        elif not (re.match(
                  r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                  email)):
            error = "You did not enter a valid email address."
        # Ensure the email does not match a current user
        elif User.get_by_email(email):
            error = "A user with that email already exists."
        # Register the new user
        else:
            pw_hash = self.make_pw_hash(email, password, salt)
            user = User(
                email=db.Email(email),
                name=name,
                pw_hash=pw_hash,
                salt=salt
            )
            user_key = user.put()
            uid = user_key.id()
            self.set_cookie("user", str(uid), "/", True)
            self.redirect("/")
        self.render("signup.html", error=error)


class SignInPage(Handler):
    """Handler for the sign in page"""

    def get(self):
        self.render("signin.html")

    def post(self, error=None):
        email = self.request.get("email")
        password = self.request.get("password")

        if len(email) == 0 or len(password) == 0:
            error = "Missing one or more required fields."
        user = User.get_by_email(email)
        if not user:
            error = "Found no user with email {0}.".format(email)
        elif self.valid_pw(email, password, user.pw_hash):
            uid = user.key().id()
            self.set_cookie("user", str(uid), "/", True)
            self.redirect("/")
        else:
            error = "Username and password do not match."
        self.render("signin.html", error=error)


class SignOut(Handler):
    """Handler to clear user cookie on logout"""

    def get(self):
        self.set_cookie("user", "", "/", False)
        self.redirect("/")


class ProfilePage(Handler):
    """Handler for the profile page"""

    def get(self):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            posts = db.GqlQuery(
                "SELECT * FROM Post WHERE author = '{0}' ORDER BY created_time \
                DESC".format(user.name)
            )
            comments = db.GqlQuery(
                "SELECT * FROM Comment WHERE author = '{0}' ORDER BY created_time \
                DESC".format(user.name)
            )
            self.render("profile.html", user=user, posts=posts,
                        comments=comments)


class EditPostPage(Handler):
    """Handler for the edit post and new post pages"""

    def get(self, pid=None):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            # If this is a current post, edit the current post
            if pid:
                # Check that user created this post
                uid = self.read_cookie("user", True)
                post = Post.get_by_id(int(pid))
                if self.user_post(uid, pid):
                    self.render("edit-post.html", post=post)
                else:
                    user = User.get_by_id(int(uid))
                    comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                        {0}".format(pid))
                    self.render("view-post.html", post=post, user=user,
                                comments=comments,
                                error="You cannot edit a post you did not \
                                create")
            # Otherwise create a new post
            else:
                self.render("edit-post.html")

    def post(self, pid=None):
        title = self.request.get("title")
        content = self.request.get("content")

        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            if pid:
                # Check that user created this post
                uid = self.read_cookie("user", True)
                post = Post.get_by_id(int(pid))
                if self.user_post(uid, pid):
                    # Check to ensure title and content are not blank
                    if len(title) == 0 or len(content) == 0:
                        self.render("edit-post.html", post=post,
                                    error="Missing one or more required \
                                    fields")
                    else:
                        post.title = title
                        post.content = content
                        post.put()
                        self.redirect("/post/{0}".format(pid))
                else:
                    user = User.get_by_id(int(uid))
                    comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                             {0}".format(pid))
                    self.render("view-post.html", post=post, user=user,
                                comments=comments,
                                error="You cannot edit a post you did not \
                                create")
            else:
                # Check to ensure title and content are not blank
                if len(title) == 0 or len(content) == 0:
                    self.render("edit-post.html",
                                error="Missing one or more required fields")
                else:
                    uid = self.read_cookie("user", True)
                    user = User.get_by_id(int(uid))
                    post = Post(title=title, content=content, author=user.name)
                    post_key = post.put()
                    pid = post_key.id()
                    self.redirect("/post/{0}".format(pid))


class ViewPostPage(Handler):
    """Handler for the post pages"""

    def get(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            # Check if post exists in case of slow deletion
            if not post:
                self.redirect("/")
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                {0}".format(pid))
            self.render("view-post.html", post=post, user=user,
                        comments=comments)

    def post(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            # Check if this is the user's post
            own = False
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                {0}".format(pid))
            if self.user_post(uid, pid):
                own = True
                self.render("view-post.html", post=post, user=user,
                            comments=comments,
                            error="You cannot like your own post")
            # Check if user has already liked this post
            liked = False
            for like in user.liked_posts:
                if like == int(pid):
                    liked = True
                    self.render("view-post.html", post=post, user=user,
                                comments=comments,
                                error="You cannot like the same post twice")
            if not liked and not own:
                post.likes += 1
                post.put()
                user.liked_posts.append(int(pid))
                user.put()
                self.render("view-post.html", post=post, user=user,
                            comments=comments)


class DeletePostPage(Handler):
    """Handler for deleting a post"""

    def get(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            # Check that user created post
            uid = self.read_cookie("user", True)
            if self.user_post(uid, pid):
                post = Post.get_by_id(int(pid))
                post.delete()
                self.redirect("/")
            else:
                user = User.get_by_id(int(uid))
                post = Post.get_by_id(int(pid))
                comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                    {0}".format(pid))
                self.render("view-post.html", post=post, user=user,
                            comments=comments,
                            error="You cannot delete a post you did not \
                            create")


class CreateCommentPage(Handler):
    """Handler for commenting on a post"""

    def get(self, pid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            self.render("create-comment.html", post=post)

    def post(self, pid):
        content = self.request.get("content")

        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            # Check that content is not blank
            if len(content) == 0:
                self.render("create-comment.html", post=post,
                            error="Your comment must include content")
            else:
                uid = self.read_cookie("user", True)
                user = User.get_by_id(int(uid))
                comment = Comment(content=content, author=user.name,
                                  post_id=int(pid))
                comment.put()
                comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = \
                    {0}".format(pid))
                self.render("view-post.html", post=post, user=user,
                            comments=comments)


class EditCommentPage(Handler):
    """Handler for editing a comment"""

    def get(self, pid, cid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            comment = Comment.get_by_id(int(cid))
            # Check that this comment was created by user
            uid = self.read_cookie("user", True)
            if self.user_comment(uid, cid):
                self.render("edit-comment.html", post=post, comment=comment)
            else:
                user = User.get_by_id(int(uid))
                self.render("view-comment.html", post=post, user=user,
                            comment=comment,
                            error="You cannot edit a post you did not create")

    def post(self, pid, cid):
        content = self.request.get("content")

        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            post = Post.get_by_id(int(pid))
            comment = Comment.get_by_id(int(cid))
            # Check that user created this comment
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            if self.user_comment(uid, cid):
                # Check that content is not blank
                if len(content) == 0:
                    self.render("edit-comment.html", post=post,
                                comment=comment,
                                error="Your comment must include content")
                else:
                    comment.content = content
                    comment.put()
                    self.render("view-comment.html", post=post, user=user,
                                comment=comment)
            else:
                self.render("view-comment.html", post=post, user=user,
                            comment=comment,
                            error="You cannot edit a post you did not create")


class ViewCommentPage(Handler):
    """Handler for viewing a comment"""

    def get(self, pid, cid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            comment = Comment.get_by_id(int(cid))
            # Check if comment exists in case of slow deletion
            if not comment:
                self.redirect("/post/{0}".format(pid))
            post = Post.get_by_id(int(pid))
            uid = self.read_cookie("user", True)
            user = User.get_by_id(int(uid))
            self.render("view-comment.html", post=post, user=user,
                        comment=comment)


class DeleteCommentPage(Handler):
    """Handler for deleting a comment"""

    def get(self, pid, cid):
        # Check that user is valid
        if not self.valid_user():
            self.set_cookie("user", "", "/", False)
            self.redirect("/")
        else:
            # Check that user created comment
            uid = self.read_cookie("user", True)
            if self.user_comment(uid, cid):
                comment = Comment.get_by_id(int(cid))
                comment.delete()
                self.redirect("/post/{0}".format(pid))
            else:
                user = User.get_by_id(int(uid))
                post = Post.get_by_id(int(pid))
                comment = Comment.get_by_id(int(cid))
                self.render("view-comment.html", post=post, user=user,
                            comment=comment,
                            error="You cannot delete a comment you did not \
                            create")

app = webapp2.WSGIApplication([
    ("/", MainPage),
    ("/signup", SignUpPage),
    ("/signin", SignInPage),
    ("/signout", SignOut),
    ("/profile", ProfilePage),
    ("/post", EditPostPage),
    ("/post/(.*)/comment/(.*)/edit", EditCommentPage),
    ("/post/(.*)/comment/(.*)/delete", DeleteCommentPage),
    ("/post/(.*)/edit", EditPostPage),
    ("/post/(.*)/delete", DeletePostPage),
    ("/post/(.*)/comment", CreateCommentPage),
    ("/post/(.*)/comment/(.*)", ViewCommentPage),
    ("/post/(.*)", ViewPostPage)
], debug=True)
