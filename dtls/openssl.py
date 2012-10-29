# OpenSSL library wrapper: provide access to both OpenSSL dynamic libraries
# through ctypes. Wrtten by Ray Brown.
"""OpenSSL Wrapper

This module provides run-time access to the OpenSSL cryptographic and
protocols libraries.

Exceptions:

  OpenSSLError -- exception raised when errors occur in the OpenSSL library

Functions:

Integer constants:

  BIO_NOCLOSE -- don't destroy encapsulated resource when closing BIO
  BIO_CLOSE -- do destroy encapsulated resource when closing BIO

"""

import sys
import array
import socket
from logging import getLogger
from os import path
from err import OpenSSLError
from err import SSL_ERROR_NONE
import ctypes
from ctypes import CDLL
from ctypes import CFUNCTYPE
from ctypes import c_void_p, c_int, c_uint, c_ulong, c_char_p, c_size_t
from ctypes import c_short, c_ushort, c_ubyte, c_char
from ctypes import byref, POINTER
from ctypes import Structure, Union
from ctypes import create_string_buffer, sizeof, memmove

#
# Module initialization
#
_logger = getLogger(__name__)

#
# Library loading
#
if sys.platform.startswith('win'):
    dll_path = path.abspath(path.dirname(__file__))
    #libcrypto = CDLL(path.join(dll_path, "libeay32.dll"))
    #libssl = CDLL(path.join(dll_path, "ssleay32.dll"))
    libcrypto = CDLL(path.join(dll_path, "cygcrypto-1.0.0.dll"))
    libssl = CDLL(path.join(dll_path, "cygssl-1.0.0.dll"))
else:
    libcrypto = CDLL("libcrypto.so.1.0.0")
    libssl = CDLL("libssl.so.1.0.0")

#
# Integer constants - exported
#
BIO_NOCLOSE = 0x00
BIO_CLOSE = 0x01
SSL_VERIFY_NONE = 0x00
SSL_VERIFY_PEER = 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
SSL_VERIFY_CLIENT_ONCE = 0x04
SSL_SESS_CACHE_OFF = 0x0000
SSL_SESS_CACHE_CLIENT = 0x0001
SSL_SESS_CACHE_SERVER = 0x0002
SSL_SESS_CACHE_BOTH = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER
SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080
SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100
SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200
SSL_SESS_CACHE_NO_INTERNAL = \
  SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE
SSL_FILE_TYPE_PEM = 1

#
# Integer constants - internal
#
SSL_CTRL_SET_SESS_CACHE_MODE = 44
SSL_CTRL_SET_READ_AHEAD = 41
BIO_CTRL_DGRAM_SET_CONNECTED = 32
BIO_CTRL_DGRAM_GET_PEER = 46
BIO_CTRL_DGRAM_SET_PEER = 44
BIO_C_SET_NBIO = 102
DTLS_CTRL_LISTEN = 75

#
# Parameter data types
#
class c_long(object):
    """Long integer paramter class

    c_long must be distinguishable from c_int, as the latter is associated
    with a default error checking routine, while the former is not.
    """


class FuncParam(object):
    """Function parameter or return type"""
    @classmethod
    def from_param(cls, value):
        if not isinstance(value, cls):
            _logger.error("Parameter type mismatch: %s not of type %s",
                          value, cls)
            raise TypeError(repr(value) + " is not of type " + repr(cls))
        return value._as_parameter

    def __init__(self, value):
        self._as_parameter = value


class DTLSv1Method(FuncParam):
    def __init__(self, value):
        super(DTLSv1Method, self).__init__(value)


class SSLCTX(FuncParam):
    def __init__(self, value):
        super(SSLCTX, self).__init__(value)


class SSL(FuncParam):
    def __init__(self, value):
        super(SSL, self).__init__(value)


class BIO(FuncParam):
    def __init__(self, value):
        super(BIO, self).__init__(value)


#
# Socket address conversions
#
class sockaddr_storage(Structure):
    _fields_ = [("ss_family", c_short),
                ("pad", c_char * 126)]

class sockaddr_in(Structure):
    _fields_ = [("sin_family", c_short),
                ("sin_port", c_ushort),
                ("sin_addr", c_ulong * 1),
                ("sin_zero", c_char * 8)]

class sockaddr_in6(Structure):
    _fields_ = [("sin6_family", c_short),
                ("sin6_port", c_ushort),
                ("sin6_flowinfo", c_ulong),
                ("sin6_addr", c_ulong * 4),
                ("sin6_scope_id", c_ulong)]

class sockaddr_u(Union):
    _fields_ = [("ss", sockaddr_storage),
                ("s4", sockaddr_in),
                ("s6", sockaddr_in6)]

py_inet_ntop = getattr(socket, "inet_ntop", None)
if not py_inet_ntop:
    windll = getattr(ctypes, "windll", None)
    if windll:
        wsa_inet_ntop = getattr(windll.ws2_32, "inet_ntop", None)
    else:
        wsa_inet_ntop = None

py_inet_pton = getattr(socket, "inet_pton", None)
if not py_inet_pton:
    windll = getattr(ctypes, "windll", None)
    if windll:
        wsa_inet_pton = getattr(windll.ws2_32, "inet_pton", None)
    else:
        wsa_inet_pton = None

def inet_ntop(address_family, packed_ip):
    if py_inet_ntop:
        return py_inet_ntop(address_family,
                            array.array('L', packed_ip).tostring())
    if wsa_inet_ntop:
        string_buf = create_string_buffer(47)
        wsa_inet_ntop(address_family, packed_ip,
                      string_buf, sizeof(string_buf))
        if not string_buf.value:
            raise ValueError("wsa_inet_ntop failed with: %s" %
                             array.array('L', packed_ip).tostring())
        return string_buf.value
    if address_family == socket.AF_INET6:
        raise ValueError("Platform does not support IPv6")
    return socket.inet_ntoa(array.array('L', packed_ip).tostring())

def inet_pton(address_family, string_ip):
    if address_family == socket.AF_INET6:
        ret_packed_ip = (c_ulong * 4)()
    else:
        ret_packed_ip = (c_ulong * 1)()
    if py_inet_pton:
        ret_string = py_inet_pton(address_family, string_ip)
        ret_packed_ip[:] = array.array('L', ret_string)
    elif wsa_inet_pton:
        if wsa_inet_pton(address_family, string_ip, ret_packed_ip) != 1:
            raise ValueError("wsa_inet_pton failed with: %s" % string_ip)
    else:
        if address_family == socket.AF_INET6:
            raise ValueError("Platform does not support IPv6")
        ret_string = socket.inet_aton(string_ip)
        ret_packed_ip[:] = array.array('L', ret_string)
    return ret_packed_ip

def addr_tuple_from_sockaddr_u(su):
    if su.ss.ss_family == socket.AF_INET6:
        return (inet_ntop(socket.AF_INET6, su.s6.sin6_addr),
                socket.ntohs(su.s6.sin6_port),
                socket.ntohl(su.s6.sin6_flowinfo),
                socket.ntohl(su.s6.sin6_scope_id))
    assert su.ss.ss_family == socket.AF_INET
    return inet_ntop(socket.AF_INET, su.s4.sin_addr), \
      socket.ntohs(su.s4.sin_port)

def sockaddr_u_from_addr_tuple(address):
    su = sockaddr_u()
    if len(address) > 2:
        su.ss.ss_family = socket.AF_INET6
        su.s6.sin6_addr[:] = inet_pton(socket.AF_INET6, address[0])
        su.s6.sin6_port = socket.htons(address[1])
        su.s6.sin6_flowinfo = socket.htonl(address[2])
        su.s6.sin6_scope_id = socket.htonl(address[3])
    else:
        su.ss.ss_family = socket.AF_INET
        su.s4.sin_addr[:] = inet_pton(socket.AF_INET, address[0])
        su.s4.sin_port = socket.htons(address[1])
    return su

#
# Error handling
#
def raise_ssl_error(result, func, args, ssl):
    if not ssl:
        ssl_error = SSL_ERROR_NONE
    else:
        ssl_error = _SSL_get_error(ssl, result)
    errqueue = []
    while True:
        err = _ERR_get_error()
        if not err:
            break
        buf = create_string_buffer(512)
        _ERR_error_string_n(err, buf, sizeof(buf))
        errqueue.append((err, buf.value))
    _logger.debug("SSL error raised: ssl_error: %d, result: %d, " +
                  "errqueue: %s, func_name: %s",
                  ssl_error, result, errqueue, func.func_name)
    raise OpenSSLError(ssl_error, errqueue, result, func, args)

def find_ssl_arg(args):
    for arg in args:
        if isinstance(arg, SSL):
            return arg

def errcheck_ord(result, func, args):
    if result <= 0:
        raise_ssl_error(result, func, args, find_ssl_arg(args))
    return args

def errcheck_p(result, func, args):
    if not result:
        raise_ssl_error(result, func, args, None)
    return args

#
# Function prototypes
#
def _make_function(name, lib, args, export=True, errcheck="default"):
    assert len(args)

    def type_subst(map_type):
        if _subst.has_key(map_type):
            return _subst[map_type]
        return map_type

    sig = tuple(type_subst(i[0]) for i in args)
    if not _sigs.has_key(sig):
        _sigs[sig] = CFUNCTYPE(*sig)
    if export:
        glbl_name = name
        __all__.append(name)
    else:
        glbl_name = "_" + name
    func = _sigs[sig]((name, lib), tuple((i[2] if len(i) > 2 else 1,
                                          i[1],
                                          i[3] if len(i) > 3 else None)
                                         [:3 if len(i) > 3 else 2]
                                         for i in args[1:]))
    func.func_name = name
    if errcheck == "default":
        # Assign error checker based on return type
        if args[0][0] in (c_int,):
            errcheck = errcheck_ord
        elif args[0][0] in (c_void_p, c_char_p) or \
          isinstance(args[0][0], FuncParam):
            errcheck = errcheck_p
        else:
            errcheck = None
    if errcheck:
        func.errcheck = errcheck
    globals()[glbl_name] = func

_subst = {c_long: ctypes.c_long}
_sigs = {}
__all__ = ["BIO_NOCLOSE", "BIO_CLOSE",
           "SSL_VERIFY_NONE", "SSL_VERIFY_PEER",
           "SSL_VERIFY_FAIL_IF_NO_PEER_CERT", "SSL_VERIFY_CLIENT_ONCE",
           "SSL_SESS_CACHE_OFF", "SSL_SESS_CACHE_CLIENT",
           "SSL_SESS_CACHE_SERVER", "SSL_SESS_CACHE_BOTH",
           "SSL_SESS_CACHE_NO_AUTO_CLEAR", "SSL_SESS_CACHE_NO_INTERNAL_LOOKUP",
           "SSL_SESS_CACHE_NO_INTERNAL_STORE", "SSL_SESS_CACHE_NO_INTERNAL",
           "SSL_FILE_TYPE_PEM",
           "DTLSv1_listen",
           "BIO_dgram_set_connected",
           "BIO_dgram_get_peer", "BIO_dgram_set_peer",
           "BIO_set_nbio",
           "SSL_CTX_set_session_cache_mode", "SSL_CTX_set_read_ahead",
           "SSL_read", "SSL_write",
           "SSL_CTX_set_cookie_cb"]

map(lambda x: _make_function(*x), (
    ("SSL_library_init", libssl, ((c_int, "ret"),)),
    ("SSL_load_error_strings", libssl, ((None, "ret"),)),
    ("DTLSv1_server_method", libssl, ((DTLSv1Method, "ret"),)),
    ("DTLSv1_client_method", libssl, ((DTLSv1Method, "ret"),)),
    ("SSL_CTX_new", libssl, ((SSLCTX, "ret"), (DTLSv1Method, "meth"))),
    ("SSL_CTX_free", libssl, ((None, "ret"), (SSLCTX, "ctx"))),
    ("SSL_CTX_set_cookie_generate_cb", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_void_p, "app_gen_cookie_cb")), False),
    ("SSL_CTX_set_cookie_verify_cb", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_void_p, "app_verify_cookie_cb")),
     False),
    ("SSL_new", libssl, ((SSL, "ret"), (SSLCTX, "ctx"))),
    ("SSL_free", libssl, ((None, "ret"), (SSL, "ssl"))),
    ("SSL_set_bio", libssl,
     ((None, "ret"), (SSL, "ssl"), (BIO, "rbio"), (BIO, "wbio"))),
    ("BIO_new_dgram", libcrypto,
     ((BIO, "ret"), (c_int, "fd"), (c_int, "close_flag"))),
    ("BIO_free", libcrypto, ((c_int, "ret"), (BIO, "a"))),
    ("SSL_CTX_ctrl", libssl,
     ((c_long, "ret"), (SSLCTX, "ctx"), (c_int, "cmd"), (c_long, "larg"),
      (c_void_p, "parg")), False),
    ("BIO_ctrl", libcrypto,
     ((c_long, "ret"), (BIO, "bp"), (c_int, "cmd"), (c_long, "larg"),
      (c_void_p, "parg")), False),
    ("SSL_ctrl", libssl,
     ((c_long, "ret"), (SSL, "ssl"), (c_int, "cmd"), (c_long, "larg"),
      (c_void_p, "parg")), False),
    ("ERR_get_error", libcrypto, ((c_long, "ret"),), False),
    ("ERR_error_string_n", libcrypto,
     ((None, "ret"), (c_ulong, "e"), (c_char_p, "buf"), (c_size_t, "len")),
     False),
    ("SSL_get_error", libssl, ((c_int, "ret"), (SSL, "ssl"), (c_int, "ret")),
     False, None),
    ("SSL_CTX_set_cipher_list", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "str"))),
    ("SSL_CTX_use_certificate_file", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "file"), (c_int, "type"))),
    ("SSL_CTX_use_certificate_chain_file", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "file"))),
    ("SSL_CTX_use_PrivateKey_file", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "file"), (c_int, "type"))),
    ("SSL_CTX_load_verify_locations", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "CAfile"),
      (c_char_p, "CApath"))),
    ("SSL_CTX_set_verify", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_int, "mode"),
      (c_void_p, "verify_callback", 1, None))),
    ("SSL_accept", libssl, ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_connect", libssl, ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_set_connect_state", libssl, ((None, "ret"), (SSL, "ssl"))),
    ("SSL_set_accept_state", libssl, ((None, "ret"), (SSL, "ssl"))),
    ("SSL_do_handshake", libssl, ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_read", libssl,
     ((c_int, "ret"), (SSL, "ssl"), (c_void_p, "buf"), (c_int, "num")), False),
    ("SSL_write", libssl,
     ((c_int, "ret"), (SSL, "ssl"), (c_void_p, "buf"), (c_int, "num")), False),
    ("SSL_shutdown", libssl, ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_set_read_ahead", libssl,
     ((None, "ret"), (SSL, "ssl"), (c_int, "yes"))),
    ))

#
# Wrappers - functions generally equivalent to OpenSSL library macros
#
_rint_voidp_ubytep_uintp = CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte),
                                     POINTER(c_uint))
_rint_voidp_ubytep_uint = CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_uint)

def SSL_CTX_set_session_cache_mode(ctx, mode):
    # Returns the previous value of mode
    _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode, None)

def SSL_CTX_set_read_ahead(ctx, m):
    # Returns the previous value of m
    _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, m, None)

def SSL_CTX_set_cookie_cb(ctx, generate, verify):
    def py_generate_cookie_cb(ssl, cookie, cookie_len):
        try:
            ret_cookie = generate(SSL(ssl))
        except:
            _logger.exception("Cookie generation failed")
            return 0
        cookie_len[0] = len(ret_cookie)
        memmove(cookie, ret_cookie, cookie_len[0])
        _logger.debug("Returning cookie: %s", cookie[:cookie_len[0]])
        return 1

    def py_verify_cookie_cb(ssl, cookie, cookie_len):
        _logger.debug("Verifying cookie: %s", cookie[:cookie_len])
        try:
            verify(SSL(ssl), ''.join([chr(i) for i in cookie[:cookie_len]]))
        except:
            _logger.debug("Cookie verification failed")
            return 0
        return 1

    gen_cb = _rint_voidp_ubytep_uintp(py_generate_cookie_cb)
    ver_cb = _rint_voidp_ubytep_uint(py_verify_cookie_cb)
    _SSL_CTX_set_cookie_generate_cb(ctx, gen_cb)
    _SSL_CTX_set_cookie_verify_cb(ctx, ver_cb)
    return gen_cb, ver_cb

def BIO_dgram_set_connected(bio, peer_address):
    su = sockaddr_u_from_addr_tuple(peer_address)
    _BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, byref(su))

def BIO_dgram_get_peer(bio):
    su = sockaddr_u()
    _BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_PEER, 0, byref(su))
    return addr_tuple_from_sockaddr_u(su)

def BIO_dgram_set_peer(bio, peer_address):
    su = sockaddr_u_from_addr_tuple(peer_address)
    _BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, byref(su))

def BIO_set_nbio(bio, n):
    _BIO_ctrl(bio, BIO_C_SET_NBIO, 1 if n else 0, None)

def DTLSv1_listen(ssl):
    su = sockaddr_u()
    ret = _SSL_ctrl(ssl, DTLS_CTRL_LISTEN, 0, byref(su))
    errcheck_ord(ret, _SSL_ctrl, (ssl, DTLS_CTRL_LISTEN, 0, byref(su)))
    return addr_tuple_from_sockaddr_u(su)

def SSL_read(ssl, length):
    buf = create_string_buffer(length)
    res_len = _SSL_read(ssl, buf, length)
    return buf.raw[:res_len]

def SSL_write(ssl, data):
    str_data = str(data)
    return _SSL_write(ssl, str_data, len(str_data))
