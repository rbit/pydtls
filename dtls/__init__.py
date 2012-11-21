# PyDTLS: datagram TLS for Python. Written by Ray Brown.
"""PyDTLS package

This package exports OpenSSL's DTLS support to Python. Calling its patch
function will add the constant PROTOCOL_DTLSv1 to the Python standard library's
ssl module.  Subsequently passing a datagram socket to that module's
wrap_socket function (or instantiating its SSLSocket class with a datagram
socket) will activate this module's DTLS implementation for the returned
SSLSocket instance.

Instead of or in addition to invoking the patch functionality, the
SSLConnection class can be used directly for secure communication over datagram
sockets.

wrap_socket's parameters and their semantics have been maintained.
"""

from patch import do_patch
from sslconnection import SSLConnection
