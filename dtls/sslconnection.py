# SSL connection: state and behavior associated with the connection between
# the OpenSSL library and an individual peer. Written by Ray Brown.
"""SSL Connection

This module encapsulates the state and behavior associated with the connection
between the OpenSSL library and an individual peer when using the DTLS
protocol. It defines the application side of the interface of a client with a
DTLS server, and of a server with a DTLS client.

Classes:

  SSLConnection -- DTLS peer association

Integer constants:

  PROTOCOL_DTLSv1

The cert group must coincide in meaning and value with the one of the standard
library's ssl module, since its values can be passed to this module.

  CERT_NONE
  CERT_OPTIONAL
  CERT_REQUIRED
"""

import errno
import socket
import hmac
from logging import getLogger
from os import urandom
from weakref import proxy
from err import OpenSSLError, InvalidSocketError
from err import raise_ssl_error
from err import SSL_ERROR_WANT_READ, ERR_COOKIE_MISMATCH, ERR_NO_CERTS
from openssl import *

_logger = getLogger(__name__)

PROTOCOL_DTLSv1 = 256
CERT_NONE = 0
CERT_OPTIONAL = 1
CERT_REQUIRED = 2

#
# One-time global OpenSSL library initialization
#
SSL_library_init()
SSL_load_error_strings()


class _Rsrc(object):
    """Wrapper base for library-owned resources"""
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value


class _CTX(_Rsrc):
    """SSL_CTX wrapper"""
    def __init__(self, value):
        super(_CTX, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing SSL CTX: %d", self._value._as_parameter)
        SSL_CTX_free(self._value)
        self._value = None


class _BIO(_Rsrc):
    """BIO wrapper"""
    def __init__(self, value):
        super(_BIO, self).__init__(value)
        self.owned = True

    def disown(self):
        self.owned = False

    def __del__(self):
        if self.owned:
            _logger.debug("Freeing BIO: %d", self._value._as_parameter)
            BIO_free(self._value)
            self.owned = False
        self._value = None


class _SSL(_Rsrc):
    """SSL structure wrapper"""
    def __init__(self, value):
        super(_SSL, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing SSL: %d", self._value._as_parameter)
        SSL_free(self._value)
        self._value = None


class _CallbackProxy(object):
    """Callback gateway to an SSLConnection object

    This class forms a weak connection between a callback method and
    an SSLConnection object. It can be passed as a callback callable
    without creating a strong reference through bound methods of
    the SSLConnection.
    """

    def __init__(self, cbm):
        self.ssl_connection = proxy(cbm.im_self)
        self.ssl_func = cbm.im_func

    def __call__(self, *args, **kwargs):
        return self.ssl_func(self.ssl_connection, *args, **kwargs)


class SSLConnection(object):
    """DTLS peer association

    This class associates two DTLS peer instances, wrapping OpenSSL library
    state including SSL (struct ssl_st), SSL_CTX, and BIO instances.
    """

    _rnd_key = urandom(16)

    def _init_server(self):
        if self.sock.type != socket.SOCK_DGRAM:
            raise InvalidSocketError("sock must be of type SOCK_DGRAM")

        from demux import UDPDemux
        self.udp_demux = UDPDemux(self.sock)
        self.rsock = self.udp_demux.get_connection(None)
        self.wbio = _BIO(BIO_new_dgram(self.sock.fileno(), BIO_NOCLOSE))
        self.rbio = _BIO(BIO_new_dgram(self.rsock.fileno(), BIO_NOCLOSE))
        self.ctx = _CTX(SSL_CTX_new(DTLSv1_server_method()))
        SSL_CTX_set_session_cache_mode(self.ctx.value, SSL_SESS_CACHE_OFF)
        if self.cert_reqs == CERT_NONE:
            verify_mode = SSL_VERIFY_NONE
        elif self.cert_reqs == CERT_OPTIONAL:
            verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE
        else:
            verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | \
              SSL_VERIFY_FAIL_IF_NO_PEER_CERT
        self.listening = False
        self.listening_peer_address = None
        self.pending_peer_address = None
        self._config_ssl_ctx(verify_mode)
        self.cb_keepalive = SSL_CTX_set_cookie_cb(
            self.ctx.value,
            _CallbackProxy(self._generate_cookie_cb),
            _CallbackProxy(self._verify_cookie_cb))
        self.ssl = _SSL(SSL_new(self.ctx.value))
        SSL_set_accept_state(self.ssl.value)

    def _init_client(self):
        if self.sock.type != socket.SOCK_DGRAM:
            raise InvalidSocketError("sock must be of type SOCK_DGRAM")

        self.wbio = _BIO(BIO_new_dgram(self.sock.fileno(), BIO_NOCLOSE))
        self.rbio = self.wbio
        self.ctx = _CTX(SSL_CTX_new(DTLSv1_client_method()))
        if self.cert_reqs == CERT_NONE:
            verify_mode = SSL_VERIFY_NONE
        else:
            verify_mode = SSL_VERIFY_PEER
        self._config_ssl_ctx(verify_mode)
        self.ssl = _SSL(SSL_new(self.ctx.value))
        SSL_set_connect_state(self.ssl.value)

    def _config_ssl_ctx(self, verify_mode):
        SSL_CTX_set_verify(self.ctx.value, verify_mode)
        SSL_CTX_set_read_ahead(self.ctx.value, 1)
        if self.certfile:
            SSL_CTX_use_certificate_chain_file(self.ctx.value, self.certfile)
        if self.keyfile:
            SSL_CTX_use_PrivateKey_file(self.ctx.value, self.keyfile,
                                        SSL_FILE_TYPE_PEM)
        if self.ca_certs:
            SSL_CTX_load_verify_locations(self.ctx.value, self.ca_certs, None)
        if self.ciphers:
            SSL_CTX_set_cipher_list(self.ctx.value, self.ciphers)

    def _copy_server(self):
        source = self.sock
        self.sock = source.sock
        self.udp_demux = source.udp_demux
        self.rsock = self.udp_demux.get_connection(source.pending_peer_address)
        self.wbio = _BIO(BIO_new_dgram(self.sock.fileno(), BIO_NOCLOSE))
        self.rbio = _BIO(BIO_new_dgram(self.rsock.fileno(), BIO_NOCLOSE))
        BIO_dgram_set_peer(self.wbio.value, source.pending_peer_address)
        self.ctx = source.ctx
        self.ssl = source.ssl
        new_source_wbio = _BIO(BIO_new_dgram(source.sock.fileno(),
                                             BIO_NOCLOSE))
        new_source_rbio = _BIO(BIO_new_dgram(source.rsock.fileno(),
                                             BIO_NOCLOSE))
        source.ssl = _SSL(SSL_new(self.ctx.value))
        source.rbio = new_source_rbio
        source.wbio = new_source_wbio
        SSL_set_bio(source.ssl.value,
                    new_source_rbio.value,
                    new_source_wbio.value)
        new_source_rbio.disown()
        new_source_wbio.disown()

    def _check_nbio(self):
        BIO_set_nbio(self.wbio.value, self.sock.gettimeout() is not None)
        if self.wbio is not self.rbio:
            BIO_set_nbio(self.rbio.value, self.rsock.gettimeout() is not None)

    def _get_cookie(self, ssl):
        assert self.listening
        assert self.ssl.value._as_parameter == ssl._as_parameter
        if self.listening_peer_address:
            peer_address = self.listening_peer_address
        else:
            peer_address = BIO_dgram_get_peer(self.rbio.value)
        cookie_hmac = hmac.new(self._rnd_key, str(peer_address))
        return cookie_hmac.digest()

    def _generate_cookie_cb(self, ssl):
        return self._get_cookie(ssl)

    def _verify_cookie_cb(self, ssl, cookie):
        if self._get_cookie(ssl) != cookie:
            raise Exception("DTLS cookie mismatch")

    def __init__(self, sock, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=CERT_NONE,
                 ssl_version=PROTOCOL_DTLSv1, ca_certs=None,
                 do_handshake_on_connect=True,
                 suppress_ragged_eofs=True, ciphers=None):
        """Constructor

        Arguments:
        these arguments match the ones of the SSLSocket class in the
        standard library's ssl module
        """

        if keyfile and not certfile or certfile and not keyfile:
            raise_ssl_error(ERR_BOTH_KEY_CERT_FILES)
        if server_side and not keyfile:
            raise_ssl_error(ERR_BOTH_KEY_CERT_FILES_SVR)
        if cert_reqs != CERT_NONE and not ca_certs:
            raise_ssl_error(ERR_NO_CERTS)

        if not ciphers:
            ciphers = "DEFAULT"

        self.sock = sock
        self.keyfile = keyfile
        self.certfile = certfile
        self.cert_reqs = cert_reqs
        self.ca_certs = ca_certs
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self.ciphers = ciphers

        if isinstance(sock, SSLConnection):
            self._copy_server()
        elif server_side:
            self._init_server()
        else:
            self._init_client()

        SSL_set_bio(self.ssl.value, self.rbio.value, self.wbio.value)
        self.rbio.disown()
        self.wbio.disown()

    def listen(self):
        """Server-side cookie exchange

        This method reads datagrams from the socket and initiates cookie
        exchange, upon whose successful conclusion one can then proceed to
        the accept method. Alternatively, accept can be called directly, in
        which case it will call this method. In order to prevent denial-of-
        service attacks, only a small, constant set of computing resources
        are used during the listen phase.

        On some platforms, listen must be called so that packets will be
        forwarded to accepted connections. Doing so is therefore recommened
        in all cases for portable code.

        Return value: a peer address if a datagram from a new peer was
        encountered, None if a datagram for a known peer was forwarded
        """

        self.pending_peer_address = None
        try:
            peer_address = self.udp_demux.service()
        except socket.timeout:
            peer_address = None
        except socket.error as sock_err:
            if sock_err.errno != errno.EWOULDBLOCK:
                _logger.exception("Unexpected socket error in listen")
                raise
            peer_address = None

        if not peer_address:
            _logger.debug("Listen returning without peer")
            return

        # The demux advises that a datagram from a new peer may have arrived
        if type(peer_address) is tuple:
            # For this type of demux, the write BIO must be pointed at the peer
            BIO_dgram_set_peer(self.wbio.value, peer_address)
            self.udp_demux.forward()
            self.listening_peer_address = peer_address

        self._check_nbio()
        self.listening = True
        try:
            _logger.debug("Invoking DTLSv1_listen for ssl: %d",
                          self.ssl.value._as_parameter)
            dtls_peer_address = DTLSv1_listen(self.ssl.value)
        except OpenSSLError as err:
            if err.ssl_error == SSL_ERROR_WANT_READ:
                # This method must be called again to forward the next datagram
                _logger.debug("DTLSv1_listen must be resumed")
                return
            elif err.errqueue and err.errqueue[0][0] == ERR_COOKIE_MISMATCH:
                _logger.debug("Mismatching cookie received; aborting handshake")
                return
            _logger.exception("Unexpected error in DTLSv1_listen")
            raise
        finally:
            self.listening = False
            self.listening_peer_address = None
        if type(peer_address) is tuple:
            _logger.debug("New local peer: %s", dtls_peer_address)
            self.pending_peer_address = peer_address
        else:
            self.pending_peer_address = dtls_peer_address
        _logger.debug("New peer: %s", self.pending_peer_address)
        return self.pending_peer_address

    def accept(self):
        """Server-side UDP connection establishment

        This method returns a server-side SSLConnection object, connected to
        that peer most recently returned from the listen method and not yet
        connected. If there is no such peer, then the listen method is invoked.

        Return value: SSLConnection connected to a new peer, None if packet
        forwarding only to an existing peer occurred.
        """

        if not self.pending_peer_address:
            if not self.listen():
                _logger.debug("Accept returning without connection")
                return
        new_conn = SSLConnection(self, self.keyfile, self.certfile, True,
                                 self.cert_reqs, PROTOCOL_DTLSv1,
                                 self.ca_certs, self.do_handshake_on_connect,
                                 self.suppress_ragged_eofs, self.ciphers)
        self.pending_peer_address = None
        if self.do_handshake_on_connect:
            # Note that since that connection's socket was just created in its
            # constructor, the following operation must be blocking; hence
            # handshake-on-connect can only be used with a routing demux if
            # listen is serviced by a separate application thread, or else we
            # will hang in this call
            new_conn.do_handshake()
        _logger.debug("Accept returning new connection for new peer")
        return new_conn

    def connect(self, peer_address):
        """Client-side UDP connection establishment

        This method connects this object's underlying socket. It subsequently
        performs a handshake if do_handshake_on_connect was set during
        initialization.

        Arguments:
        peer_address - address tuple of server peer
        """

        self.sock.connect(peer_address)
        BIO_dgram_set_connected(self.wbio.value, peer_address)
        assert self.wbio is self.rbio
        if self.do_handshake_on_connect:
            self.do_handshake()

    def do_handshake(self):
        """Perform a handshake with the peer

        This method forces an explicit handshake to be performed with either
        the client or server peer.
        """

        _logger.debug("Initiating handshake...")
        self._check_nbio()
        SSL_do_handshake(self.ssl.value)
        _logger.debug("...completed handshake")

    def read(self, len=1024):
        """Read data from connection

        Read up to len bytes and return them.
        Arguments:
        len -- maximum number of bytes to read

        Return value:
        string containing read bytes
        """

        self._check_nbio()
        return SSL_read(self.ssl.value, len)

    def write(self, data):
        """Write data to connection

        Write data as string of bytes.

        Arguments:
        data -- buffer containing data to be written

        Return value:
        number of bytes actually transmitted
        """

        self._check_nbio()
        return SSL_write(self.ssl.value, data)

    def shutdown(self):
        """Shut down the DTLS connection

        This method attemps to complete a bidirectional shutdown between
        peers. For non-blocking sockets, it should be called repeatedly until
        it no longer raises continuation request exceptions.
        """

        self._check_nbio()
        try:
            SSL_shutdown(self.ssl.value)
        except OpenSSLError as err:
            if err.result == 0:
                # close-notify alert was just sent; wait for same from peer
                # Note: while it might seem wise to suppress further read-aheads
                # with SSL_set_read_ahead here, doing so causes a shutdown
                # failure (ret: -1, SSL_ERROR_SYSCALL) on the DTLS shutdown
                # initiator side.
                SSL_shutdown(self.ssl.value)
            else:
                raise
