# -*- encoding: utf-8 -*-

import datetime
import select

from logging import getLogger

import ssl
import socket
from dtls import do_patch
do_patch()

_logger = getLogger(__name__)


class _ClientSession(object):

    def __init__(self, host, port, handshake_done=False):
        self.host = host
        self.port = int(port)
        self.handshake_done = handshake_done

    def getAddr(self):
        return self.host, self.port


class DtlsSocket(object):

    def __init__(self,
                 host,
                 port,
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
                 user_mtu=None):

        self._ssl_logging = False
        self._peer = (host, int(port))
        self._server_side = server_side
        self._ciphers = ciphers
        self._curves = curves
        self._sigalgs = sigalgs
        self._user_mtu = user_mtu

        self._sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                     keyfile=keyfile,
                                     certfile=certfile,
                                     server_side=self._server_side,
                                     cert_reqs=cert_reqs,
                                     ssl_version=ssl_version,
                                     ca_certs=ca_certs,
                                     do_handshake_on_connect=do_handshake_on_connect,
                                     ciphers=self._ciphers,
                                     cb_user_ssl_ctx_config=self.user_ssl_ctx_config,
                                     cb_user_ssl_config=self.user_ssl_config)

        if self._server_side:
            self._clients = {}
            self._timeout = None

            self._sock.bind(self._peer)
            self._sock.listen(0)
        else:
            self._sock.connect(self._peer)

    def user_ssl_ctx_config(self, _ctx):
        _ctx.set_ssl_logging(self._ssl_logging)
        if self._ciphers:
            _ctx.set_ciphers(self._ciphers)
        if self._curves:
            _ctx.set_curves(self._curves)
        if self._sigalgs:
            _ctx.set_sigalgs(self._sigalgs)
        if self._server_side:
            _ctx.build_cert_chain()
            _ctx.set_ecdh_curve()  # ("secp256k1")

    def user_ssl_config(self, _ssl):
        if self._user_mtu:
            _ssl.set_mtu(self._user_mtu)

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

        else:
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

            for conn in self._getClientReadingSockets():
                if conn.get_timeout():
                    conn.handle_timeout()

        raise socket.timeout

    def _recvfrom_on_client_side(self, bufsize, flags):
        try:
            buf = self._sock.recv(bufsize, flags)

        except ssl.SSLError as e_ssl:
            if e_ssl.args[0] == ssl.SSL_ERROR_ZERO_RETURN:
                return '', self._peer
            elif e_ssl.args[0] in [ssl.SSL_ERROR_SSL, ssl.SSL_ERROR_SYSCALL]:
                raise
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
                # elif e_ssl.args[0] in [ssl.SSL_ERROR_SSL, ]:
                #     # no ciphers available
                #     if e_ssl.args[1][0][0] in [336081077, ]:
                #         raise
                raise

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
            pass

        else:
            if ret:
                client, addr = ret
                host, port = addr
                if client in self._clients:
                    raise
                self._clients[client] = _ClientSession(host=host, port=port)

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
            ret = conn.send(data.raw)
            _logger.debug('To client %s ... bytes sent %s' % (str(self._clients[conn].getAddr()), str(ret)))

        except Exception as e_write:
            raise

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
