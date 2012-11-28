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
    _routing = True
else:
    from osnet import UDPDemux
    _routing = False
_default_demux = None

def force_routing_demux():
    global _routing
    if _routing:
        return False  # no change - already loaded
    global UDPDemux, _default_demux
    import router
    _default_demux = UDPDemux
    UDPDemux = router.UDPDemux
    _routing = True
    return True  # new router loaded and switched

def reset_default_demux():
    global UDPDemux, _routing, _default_demux
    if _default_demux:
        UDPDemux = _default_demux
        _default_demux = None
        _routing = not _routing

__all__ = ["UDPDemux", "force_routing_demux", "reset_default_demux"]
