from __future__ import unicode_literals

import base64
import binascii
import hashlib

from django.dispatch import receiver
from django.conf import settings
from django.test.signals import setting_changed
from django.utils import importlib
from django.utils.datastructures import SortedDict
from django.utils.encoding import force_bytes, force_str, force_text
from collections import OrderedDict
from django.core.exceptions import ImproperlyConfigured
from django.utils.crypto import (
    pbkdf2, constant_time_compare, get_random_string)
from django.utils.translation import ugettext_noop as _
from django.contrib.auth.hashers import *


UNUSABLE_PASSWORD = '!'  # This will never be a valid encoded hash
HASHERS = None  # lazily loaded from PASSWORD_HASHERS
MAXIMUM_PASSWORD_LENGTH = 4096  # The maximum length a password can be to prevent DoS
PREFERRED_HASHER = None  # defaults to first item in PASSWORD_HASHERS


def password_max_length(max_length):
    def inner(fn):
        def wrapper(self, password, *args, **kwargs):
            if len(password) > max_length:
                raise ValueError("Invalid password; Must be less than or equal"
                                 " to %d bytes" % max_length)
            return fn(self, password, *args, **kwargs)
        return wrapper
    return inner

class BCryptSHA256PasswordHasher(BasePasswordHasher):
    """
    Secure password hashing using the bcrypt algorithm (recommended)

    This is considered by many to be the most secure algorithm but you
    must first install the bcrypt library.  Please be warned that
    this library depends on native C code and might cause portability
    issues.
    """
    algorithm = "bcrypt_sha256"
    digest = hashlib.sha256
    library = ("bcrypt", "bcrypt")
    rounds = 13

    def salt(self):
        bcrypt = self._load_library()
        return bcrypt.gensalt(self.rounds)

    @password_max_length(MAXIMUM_PASSWORD_LENGTH)
    def encode(self, password, salt):
        bcrypt = self._load_library()

        # Hash the password prior to using bcrypt to prevent password truncation
        #   See: https://code.djangoproject.com/ticket/20138
        if self.digest is not None:
            # We use binascii.hexlify here because Python3 decided that a hex encoded
            #   bytestring is somehow a unicode.
            password = binascii.hexlify(self.digest(force_bytes(password)).digest())
        else:
            password = force_bytes(password)

        data = bcrypt.hashpw(password, salt)
        return "%s$%s" % (self.algorithm, force_text(data))

    @password_max_length(MAXIMUM_PASSWORD_LENGTH)
    def verify(self, password, encoded):
        algorithm, data = encoded.split('$', 1)
        assert algorithm == self.algorithm
        bcrypt = self._load_library()

        # Hash the password prior to using bcrypt to prevent password truncation
        #   See: https://code.djangoproject.com/ticket/20138
        if self.digest is not None:
            # We use binascii.hexlify here because Python3 decided that a hex encoded
            #   bytestring is somehow a unicode.
            password = binascii.hexlify(self.digest(force_bytes(password)).digest())
        else:
            password = force_bytes(password)

        # Ensure that our data is a bytestring
        data = force_bytes(data)

        return constant_time_compare(data, bcrypt.hashpw(password, data))

    def safe_summary(self, encoded):
        algorithm, empty, algostr, work_factor, data = encoded.split('$', 4)
        assert algorithm == self.algorithm
        salt, checksum = data[:22], data[22:]
        return OrderedDict([
            (_('algorithm'), algorithm),
            (_('work factor'), work_factor),
            (_('salt'), mask_hash(salt)),
            (_('checksum'), mask_hash(checksum)),
        ])