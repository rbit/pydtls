# -*- encoding: utf-8 -*-

# DTLS Socket: A wrapper for a server and client using a DTLS connection.

# Copyright 2017 Björn Freise
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# The License is also distributed with this work in the file named "LICENSE."
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""DTLS Socket

This wrapper encapsulates the state and behavior associated with the connection
between the OpenSSL library and an individual peer when using the DTLS
protocol.

Classes:

  DtlsSocket -- DTLS Socket wrapper for use as a client or server
"""

import select

from logging import getLogger

import ssl
import socket
from patch import do_patch
do_patch()
from sslconnection import SSLContext, SSL
from sslconnection import SSL_BUILD_CHAIN_FLAG_NONE, SSL_BUILD_CHAIN_FLAG_UNTRUSTED, \
    SSL_BUILD_CHAIN_FLAG_NO_ROOT, SSL_BUILD_CHAIN_FLAG_CHECK

_logger = getLogger(__name__)


class DtlsSocket(object):

    class _ClientSession(object):

        def __init__(self, host, port, handshake_done=False):
            self.host = host
            self.port = int(port)
            self.handshake_done = handshake_done

        def getAddr(self):
            return self.host, self.port

    def __init__(self,
                 peerOrSock,
                 keyfile=None,
                 certfile=None,
                 server_side=False,
                 cert_reqs=ssl.CERT_NONE,
                 ssl_version=ssl.PROTOCOL_DTLSv1_2,
                 ca_certs=None,
                 do_handshake_on_connect=False,
                 suppress_ragged_eofs=True,
                 ciphers=None,
                 curves=None,
                 sigalgs=None,
                 user_mtu=None,
                 server_key_exchange_curve=None,
                 server_cert_options=SSL_BUILD_CHAIN_FLAG_NONE):

        if server_cert_options is None:
            server_cert_options = SSL_BUILD_CHAIN_FLAG_NONE

        self._ssl_logging = False
        self._peer = None
        self._server_side = server_side
        self._ciphers = ciphers
        self._curves = curves
        self._sigalgs = sigalgs
        self._user_mtu = user_mtu
        self._server_key_exchange_curve = server_key_exchange_curve
        self._server_cert_options = server_cert_options

        # Default socket creation
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if isinstance(peerOrSock, tuple):
            # Address tuple
            self._peer = peerOrSock
        else:
            # Socket, use given
            sock = peerOrSock

        self._sock = ssl.wrap_socket(sock,
                                     keyfile=keyfile,
                                     certfile=certfile,
                                     server_side=self._server_side,
                                     cert_reqs=cert_reqs,
                                     ssl_version=ssl_version,
                                     ca_certs=ca_certs,
                                     do_handshake_on_connect=do_handshake_on_connect,
                                     suppress_ragged_eofs=suppress_ragged_eofs,
                                     ciphers=self._ciphers,
                                     cb_user_config_ssl_ctx=self.user_config_ssl_ctx,
                                     cb_user_config_ssl=self.user_config_ssl)

        if self._server_side:
            self._clients = {}
            self._timeout = None

            if self._peer:
                self._sock.bind(self._peer)
                self._sock.listen(0)
        else:
            if self._peer:
                self._sock.connect(self._peer)

    def __getattr__(self, item):
        if hasattr(self, "_sock") and hasattr(self._sock, item):
            return getattr(self._sock, item)
        raise AttributeError

    def user_config_ssl_ctx(self, _ctx):
        """

        :param SSLContext _ctx:
        """
        _ctx.set_ssl_logging(self._ssl_logging)
        if self._ciphers:
            _ctx.set_ciphers(self._ciphers)
        if self._curves:
            _ctx.set_curves(self._curves)
        if self._sigalgs:
            _ctx.set_sigalgs(self._sigalgs)
        if self._server_side:
            _ctx.build_cert_chain(flags=self._server_cert_options)
            _ctx.set_ecdh_curve(curve_name=self._server_key_exchange_curve)

    def user_config_ssl(self, _ssl):
        """

        :param SSL _ssl:
        """
        if self._user_mtu:
            _ssl.set_link_mtu(self._user_mtu)

    def settimeout(self, t):
        if self._server_side:
            self._timeout = t
        else:
            self._sock.settimeout(t)

    def close(self):
        if self._server_side:
            for cli in self._clients.keys():
                cli.close()
        else:
            self._sock.unwrap()
        self._sock.close()

    def write(self, data):
        # return self._sock.write(data)
        return self.sendto(data, self._peer)

    def read(self, len=1024):
        # return self._sock.read(len=len)
        return self.recvfrom(len)[0]

    def recvfrom(self, bufsize, flags=0):
        if self._server_side:
            return self._recvfrom_on_server_side(bufsize, flags=flags)
        else:
            return self._recvfrom_on_client_side(bufsize, flags=flags)

    def _recvfrom_on_server_side(self, bufsize, flags):
        try:
            r, _, _ = select.select(self._getAllReadingSockets(), [], [], self._timeout)

        except socket.timeout as e_timeout:
            raise e_timeout

        try:
            for conn in r:  # type: ssl.SSLSocket
                if self._sockIsServerSock(conn):
                    # Connect
                    self._clientAccept(conn)
                else:
                    # Handshake
                    if not self._clientHandshakeDone(conn):
                        self._clientDoHandshake(conn)
                    # Normal read
                    else:
                        buf = self._clientRead(conn, bufsize)
                        if buf and conn in self._clients:
                            return buf, self._clients[conn].getAddr()

        except Exception as e:
            raise e

        try:
            for conn in self._getClientReadingSockets():
                if conn.get_timeout():
                    conn.handle_timeout()

        except Exception as e:
            raise e

        raise socket.timeout

    def _recvfrom_on_client_side(self, bufsize, flags):
        try:
            buf = self._sock.recv(bufsize, flags)

        except ssl.SSLError as e_ssl:
            if e_ssl.args[0] == ssl.SSL_ERROR_ZERO_RETURN:
                return '', self._peer
            elif e_ssl.args[0] in [ssl.SSL_ERROR_SSL, ssl.SSL_ERROR_SYSCALL]:
                raise e_ssl
            else:  # like in [ssl.SSL_ERROR_WANT_READ, ...]
                pass

        else:
            if buf:
                return buf, self._peer

        raise socket.timeout

    def sendto(self, buf, address):
        if self._server_side:
            return self._sendto_from_server_side(buf, address)
        else:
            return self._sendto_from_client_side(buf, address)

    def _sendto_from_server_side(self, buf, address):
        for conn, client in self._clients.iteritems():
            if client.getAddr() == address:
                return self._clientWrite(conn, buf)
        return 0

    def _sendto_from_client_side(self, buf, address):
        while True:
            try:
                bytes_sent = self._sock.send(buf)

            except ssl.SSLError as e_ssl:
                if str(e_ssl).startswith("503:"):
                    # The write operation timed out
                    continue
                raise e_ssl

            else:
                if bytes_sent:
                    break

        return bytes_sent

    def _getClientReadingSockets(self):
        return [x for x in self._clients.keys()]

    def _getAllReadingSockets(self):
        return [self._sock] + self._getClientReadingSockets()

    def _sockIsServerSock(self, conn):
        return conn is self._sock

    def _clientHandshakeDone(self, conn):
        return conn in self._clients and self._clients[conn].handshake_done is True

    def _clientAccept(self, conn):
        _logger.debug('+' * 60)
        ret = None

        try:
            ret = conn.accept()
            _logger.debug('Accept returned with ... %s' % (str(ret)))

        except Exception as e_accept:
            raise e_accept

        else:
            if ret:
                client, addr = ret
                host, port = addr
                if client in self._clients:
                    raise ValueError
                self._clients[client] = self._ClientSession(host=host, port=port)

                self._clientDoHandshake(client)

    def _clientDoHandshake(self, conn):
        _logger.debug('-' * 60)
        conn.setblocking(False)

        try:
            conn.do_handshake()
            _logger.debug('Connection from %s succesful' % (str(self._clients[conn].getAddr())))

            self._clients[conn].handshake_done = True

        except ssl.SSLError as e_handshake:
            if str(e_handshake).startswith("504:"):
                pass
            elif e_handshake.args[0] == ssl.SSL_ERROR_WANT_READ:
                pass
            else:
                raise e_handshake

    def _clientRead(self, conn, bufsize=4096):
        _logger.debug('*' * 60)
        ret = None

        try:
            ret = conn.recv(bufsize)
            _logger.debug('From client %s ... bytes received %s' % (str(self._clients[conn].getAddr()), str(len(ret))))

        except ssl.SSLError as e_read:
            if e_read.args[0] == ssl.SSL_ERROR_ZERO_RETURN:
                self._clientDrop(conn)
            elif e_read.args[0] in [ssl.SSL_ERROR_SSL, ssl.SSL_ERROR_SYSCALL]:
                self._clientDrop(conn, error=e_read)
            else:  # like in [ssl.SSL_ERROR_WANT_READ, ...]
                pass

        return ret

    def _clientWrite(self, conn, data):
        _logger.debug('#' * 60)
        ret = None

        try:
            _data = data
            if False:
                _data = data.raw
            ret = conn.send(_data)
            _logger.debug('To client %s ... bytes sent %s' % (str(self._clients[conn].getAddr()), str(ret)))

        except Exception as e_write:
            raise e_write

        return ret

    def _clientDrop(self, conn, error=None):
        _logger.debug('$' * 60)

        try:
            if error:
                _logger.debug('Drop client %s ... with error: %s' % (self._clients[conn].getAddr(), error))
            else:
                _logger.debug('Drop client %s' % str(self._clients[conn].getAddr()))

            if conn in self._clients:
                del self._clients[conn]
            conn.unwrap()
            conn.close()

        except Exception as e_drop:
            pass
