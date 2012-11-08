# PyDTLS reloader. Written by Ray Brown.
"""PyDTLS package reloader

This script reloads all modules of the DTLS package. This can be useful in
runtime environments that usually persist across package file edits, such as
the IPython shell.
"""

import dtls
import dtls.err
import dtls.util
import dtls.sslconnection
import dtls.x509
import dtls.openssl
import dtls.demux
import dtls.demux.router

def main():
    reload(dtls)
    reload(dtls.err)
    reload(dtls.util)
    reload(dtls.sslconnection)
    reload(dtls.x509)
    reload(dtls.openssl)
    reload(dtls.demux)
    reload(dtls.demux.router)
    reload(dtls.sslconnection)
    reload(dtls.x509)

if __name__ == "__main__":
    main()
