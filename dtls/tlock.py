# TLock: OpenSSL lock support on thread-enabled systems. Written by Ray Brown.
"""TLock

This module provides the callbacks required by the OpenSSL library in situations
where it is being entered concurrently by multiple threads. This module is
enagaged automatically by the PyDTLS package on systems that have Python
threading support. It does not have client-visible components.
"""

from logging import getLogger
from openssl import *

try:
    import threading
except ImportError:
    pass

_logger = getLogger(__name__)
DO_DEBUG_LOG = False

def tlock_init():
    if not globals().has_key("threading"):
        return  # nothing to configure
    # The standard library ssl module's lock implementation is more efficient;
    # do not override it if it has been established
    if CRYPTO_get_id_callback():
        return
    global _locks
    num_locks = CRYPTO_num_locks()
    _locks = tuple(threading.Lock() for _ in range(num_locks))
    CRYPTO_set_locking_callback(_locking_function)

def _locking_function(mode, n, file, line):
    if DO_DEBUG_LOG:
        _logger.debug("Thread lock:  mode: %d, n: %d, file: %s, line: %d",
                      mode, n, file, line)
    if mode & CRYPTO_LOCK:
        _locks[n].acquire()
    else:
        _locks[n].release()
