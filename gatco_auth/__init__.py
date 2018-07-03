# -*- coding: utf-8 -*-
import time
import base64
import hashlib
import hmac
import sys
import uuid

from passlib.context import CryptContext
from collections import namedtuple
from functools import partial, wraps
from inspect import isawaitable

from gatco import response
from gatco.exceptions import ServerError

__version__ = '0.2.0.dev0'

__all__ = ['Auth', 'User']

#: A User proxy type, used by default implementation of :meth:`Auth.load_user`
#User = namedtuple('User', 'id name'.split())

class Auth:
    """Authentication Manager."""

    password_hash = "plaintext"
    password_salt = None
    password_schemas = [
        'bcrypt',
        'des_crypt',
        'pbkdf2_sha256',
        'pbkdf2_sha512',
        'sha256_crypt',
        'sha512_crypt',
        # And always last one...
        'plaintext'
    ]
    deprecated_password_schemas = ['auto']
    pwd_context = None

    def __init__(self, app=None, id_attribute="id"):
        self.id_attribute = id_attribute
        self.app = None
        self.expire = 0
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Setup with application's configuration.
        This method be called automatically if the application is provided
        upon initialization
        """
        if self.app is not None:
            raise RuntimeError('already initialized with an application')
        self.app = app
        get = app.config.get
        self.login_endpoint = get('AUTH_LOGIN_ENDPOINT', 'auth.login')
        self.login_url = get('AUTH_LOGIN_URL', None)
        self.expire = get('AUTH_EXPIRE_TIME', 86400)
        self.redirect_unauthenticated = get('AUTH_REDIRECT_UNAUTHENTICATED', False)

        self.password_hash = get('AUTH_PASSWORD_HASH', "plaintext")
        self.password_salt = get('AUTH_PASSWORD_SALT', "")

        self.pwd_context = self.get_pwd_context()

        self.expire = get('AUTH_EXPIRE_TIME', 86400)

        session = get('AUTH_SESSION_NAME', get('SESSION_NAME', 'session'))

        self.session_name = session
        self.auth_session_key = get('AUTH_TOKEN_NAME', '_auth')


    def login_user(self, request, user):
        """Log in a user.
        The user object will be serialized with :meth:`Auth.serialize` and the
        result, usually a token representing the logged in user, will be
        placed into the request session.
        """
        if user is not None:
            self.get_session(request)[self.auth_session_key] = self.serialize(user)
        else:
            raise ServerError("User is required")

    def logout_user(self, request):
        """Log out any logged in user in this session.
        Return the user token or :code:`None` if no user logged in.
        """
        return self.get_session(request).pop(self.auth_session_key, None)

    def current_user(self, request):
        """Get the current logged in user.
        Return :code:`None` if no user logged in.
        """
        token = self.get_session(request).get(self.auth_session_key, None)
        if token is not None:
            return self.load_user(token)

    def login_required(self, route=None, *, user_keyword=None):
        """Decorator to make routes only accessible with authenticated user.
        Redirect visitors to login view if no user logged in.
        :param route:
            the route handler to be protected
        :param user_keyword:
            keyword only arugment, if it is not :code:`None`, and set to a
            string representing a valid python identifier, a user object
            loaded by :meth:`load_user` will be injected into the route
            handler's arguments.  This is to save from loading the user twice
            if the current user object is going to be used inside the route
            handler.
        """
        if route is None:
            return partial(self.login_required, user_keyword=user_keyword)

        @wraps(route)
        async def privileged(request, *args, **kwargs):
            user = self.current_user(request)
            if user is None:
                if self.redirect_unauthenticated:
                    u = self.login_url or request.app.url_for(self.login_endpoint)
                    return response.redirect(u)
                else:
                    raise ServerError("User is not authenticated")
            if user_keyword is not None:
                if user_keyword in kwargs:
                    raise RuntimeError(
                        'override user keyword %r in route' % user_keyword)
                kwargs[user_keyword] = user
            resp = route(request, *args, **kwargs)
            if isawaitable(resp):
                resp = await resp
            return resp
        return privileged

    def serialize(self, user):
        """Serialize the user, returns a token to be placed into session"""
        user_id = getattr(user, self.id_attribute)
        if type(user_id) is uuid.UUID:
            user_id = str(user_id)
        return {'uid': user_id, 'exprire': time.time() + self.expire}

    def serializer(self, user_serializer):
        """Decorator to set a custom user serializer"""
        self.serialize = user_serializer
        return user_serializer

    def load_user(self, token):
        """Load user with token.
        Return a User object, the default implementation use a proxy object of
        :class:`User`, Sanic-Auth can be remain backend agnostic this way.
        Override this with routine that loads user from database if needed.
        """
        if token is not None:
            if 'exprire' in token:
                if token['exprire'] < time.time():
                    return None
            return token['uid']
        return None

    def user_loader(self, load_user):
        """Decorator to set a custom user loader that loads user with token"""
        self.load_user = load_user
        return load_user

    def get_session(self, request):
        """Get the session object associated with current request"""
        return request[self.session_name]

    def encode_string(self, string):
        """Encodes a string to bytes, if it isn't already.
        :param string: The string to encode"""

        if isinstance(string, str):
            string = string.encode('utf-8')
        return string

    def get_hmac(self, password, salt):
        """Returns a Base64 encoded HMAC+SHA512 of the password signed with the salt specified
        by ``SECURITY_PASSWORD_SALT``.
        :param password: The password to sign
        """
        use_salt = None 
        if salt is not None:
            use_salt = self.password_salt + salt
        else:
        	use_salt = self.password_salt

        if (use_salt is None) or (len(use_salt) == 0):
            raise RuntimeError(
                'The configuration value `SECURITY_PASSWORD_SALT` must '
                'not be None when the value of `SECURITY_PASSWORD_HASH` is '
                'set to "%s"' % self.password_hash)

        h = hmac.new(self.encode_string(use_salt), self.encode_string(password), hashlib.sha512)
        return base64.b64encode(h.digest())

    def md5(self, data):
        return hashlib.md5(self.encode_string(data)).hexdigest()

    def encrypt_password(self, password, salt=None):
        """Encrypts the specified plaintext password using the configured encryption options.
        :param password: The plaintext password to encrypt
        """
        if self.pwd_context is None:
            raise RuntimeError('The password context must not be None')
        if self.password_hash == 'plaintext':
            return password
        signed = self.get_hmac(password, salt).decode('ascii')
        return self.pwd_context.encrypt(signed)

    def verify_password(self, password, password_hash, salt=None):
        """Returns ``True`` if the password matches the supplied hash.
        :param password: A plaintext password to verify
        :param password_hash: The expected hash value of the password (usually from your database)
        """
        if self.password_hash != 'plaintext':
            password = self.get_hmac(password, salt)

        return self.pwd_context.verify(password, password_hash)

    def get_pwd_context(self):
        pw_hash = self.password_hash
        schemes = self.password_schemas
        deprecated = self.deprecated_password_schemas
        if pw_hash not in schemes:
            allowed = (', '.join(schemes[:-1]) + ' and ' + schemes[-1])
            raise ValueError("Invalid hash scheme %r. Allowed values are %s" % (pw_hash, allowed))
        return CryptContext(schemes=schemes, default=pw_hash, deprecated=deprecated)
