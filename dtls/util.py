# Shared implementation internals. Written by Ray Brown.
"""Utilities

This module contains private implementation details shared among modules of
the PyDTLS package.
"""

from logging import getLogger

_logger = getLogger(__name__)


class _Rsrc(object):
    """Wrapper base for library-owned resources"""
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

    @property
    def raw(self):
        return self._value.raw


class _BIO(_Rsrc):
    """BIO wrapper"""
    def __init__(self, value):
        super(_BIO, self).__init__(value)
        self.owned = True

    def disown(self):
        self.owned = False

    def __del__(self):
        if self.owned:
            _logger.debug("Freeing BIO: %d", self.raw)
            from openssl import BIO_free
            BIO_free(self._value)
            self.owned = False
        self._value = None
