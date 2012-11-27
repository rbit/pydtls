# Demux loader: imports a demux module appropriate for this platform.
# Written by Ray Brown.
"""UDP Demux

A UDP demux is a wrapper for a datagram socket. The demux must be initialized
with an unconnected datagram socket, referred to as the root socket. Once
initialized, the demux will create new connections to peer endpoints upon
arrival of datagrams from a new endpoint. Such a connection is of a
socket-derived type, and will receive datagrams only from the peer endpoint for
which it was created, and that are sent to the root socket.

Connections must be used for receiving datagrams only. Outgoing traffic should
be sent through the root socket.

Varying implementations of this functionality are provided for different
platforms.
"""

import sys

if sys.platform.startswith('win') or sys.platform.startswith('cygwin'):
    from router import UDPDemux
else:
    #from osnet import UDPDemux
    from router import UDPDemux

__all__ = ["UDPDemux"]
