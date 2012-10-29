# OSNet demux: uses the OS network stack to demultiplex incoming datagrams
# among sockets bound to the same ports. Written by Ray Brown.
"""OS Network UDP Demux

This module implements a demux that uses the OS network stack to demultiplex
datagrams coming from different peers among datagram sockets that are all bound
to the port at which these datagrams are being received. The network stack is
instructed as to which socket an incoming datagram should be sent to by
connecting the destination socket to the peer endpoint.

The OSNet demux requires operating system functionality that exists in the
Linux kernel, but not in the Windows network stack.

Classes:

  UDPDemux -- a network stack configuring UDP demux

Exceptions:

  KeyError -- raised for unknown peer addresses
"""


class UDPDemux(object):
    """OS network stack configuring demux

    This class implements a demux that creates sockets connected to peer
    network endpoints, configuring the network stack to demultiplex
    incoming datagrams from these endpoints among these sockets.

    Methods:

      get_connection -- create a new connection or retrieve an existing one
      remove_connection -- remove an existing connection
      service -- this method does nothing for this type of demux
    """

    def get_connection(self, address):
        """Create or retrieve a muxed connection

        Arguments:
        address -- a peer endpoint in IPv4/v6 address format; None refers
                   to the connection for unknown peers

        Return:
        a bound, connected datagram socket instance, or the root socket
        in case address was None
        """

    def remove_connection(self, address):
        """Remove a muxed connection

        Arguments:
        address -- an address for which a muxed connection was previously
                   retrieved through get_connection, which has not yet
                   been removed

        Return:
        the socket object whose connection has been removed
        """

        return self.connections.pop(address)
