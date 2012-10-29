# PyDTLS: datagram TLS for Python. Written by Ray Brown.
"""PyDTLS package

This package exports OpenSSL's DTLS support to Python. Importing it will add
the constant PROTOCOL_DTLSv1 to the Python standard library's ssl module.
Passing a datagram socket to that module's wrap_socket function (or
instantiating its SSLSocket class with a datagram socket) will activate this
module's DTLS implementation for the returned SSLSocket instance.

wrap_socket's parameters and their semantics have been maintained.
"""
