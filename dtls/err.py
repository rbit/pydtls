# DTLS exceptions. Written by Ray Brown
"""DTLS Errors

This module defines error functionality and exception types for the dtls
package.

Classes:

  SSLError -- exception raised for I/O errors
  InvalidSocketError -- exception raised for improper socket objects
"""

from socket import error as socket_error

SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_WANT_X509_LOOKUP = 4
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6
SSL_ERROR_WANT_CONNECT = 7
SSL_ERROR_WANT_ACCEPT = 8

ERR_BOTH_KEY_CERT_FILES = 500
ERR_BOTH_KEY_CERT_FILES_SVR = 298
ERR_NO_CERTS = 331

ERR_COOKIE_MISMATCH = 0x1408A134


class SSLError(socket_error):
    """This exception is raised by modules in the dtls package."""
    def __init__(self, *args):
        super(SSLError, self).__init__(*args)


class OpenSSLError(SSLError):
    """This exception is raised when an error occurs in the OpenSSL library"""
    def __init__(self, ssl_error, errqueue, result, func, args):
        self.ssl_error = ssl_error
        self.errqueue = errqueue
        self.result = result
        self.func = func
        self.args = args
        super(OpenSSLError, self).__init__(ssl_error, errqueue,
                                           result, func, args)


class InvalidSocketError(Exception):
    """There is a problem with a socket passed to the dtls package."""
    def __init__(self, *args):
        super(InvalidSocketError, self).__init__(*args)


def raise_ssl_error(code):
    """Raise an SSL error with the given error code"""
    raise SSLError(str(code) + ": " + _ssl_errors[code])

_ssl_errors = {
    ERR_NO_CERTS: "No root certificates specified for verification " + \
                  "of other-side certificates",
    ERR_BOTH_KEY_CERT_FILES: "Both the key & certificate files " + \
                             "must be specified",
    ERR_BOTH_KEY_CERT_FILES_SVR: "Both the key & certificate files must be " + \
                                 "specified for server-side operation"
    }
