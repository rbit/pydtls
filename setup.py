#!/usr/bin/env python
# PyDTLS setup script. Written by Ray Brown.
"""PyDTLS setup script

Install or create a distribution of the PyDTLS package.
"""

from os import listdir, path, remove, rename
from sys import argv
from pickle import dump, load
from distutils.core import setup
from distutils.command.install import INSTALL_SCHEMES

# Make the root for data file installations the same as Python code
for scheme in INSTALL_SCHEMES.values():
    scheme['data'] = scheme['purelib']

NAME = "Dtls"
VERSION = "0.1"

DIST_DIR = "dist"
FORMAT_TO_SUFFIX = { "zip": ".zip",
                     "gztar": ".tar.gz",
                     "bztar": ".tar.bz2",
                     "ztar": ".tar.Z",
                     "tar": ".tar" }

def invoke_setup(data_files=None):
    data_files_file = "data_files"
    data_files_file_created = False
    try:
        if data_files:
            # Save the value of data_files with the distribution archive
            data_files_file_created = True
            with open(data_files_file, "wb") as fl:
                dump(data_files, fl)
            data_files.append(('', [data_files_file]),)
        else:
            # Load data_files from the distribution archive, if present
            try:
                with open(data_files_file, "rb") as fl:
                    data_files = load(fl)
            except IOError:
                pass
        setup(name=NAME,
              version=VERSION,
              description="Python Datagram Transport Layer Security",
              author="Ray Brown",
              author_email="code@liquibits.com",
              url="http://www.github.com/pydtls",
              packages=["dtls", "dtls.demux", "dtls.test"],
              package_data={"dtls.test": ["certs/*.pem"]},
              data_files=data_files,
              )
    finally:
        if data_files_file_created:
            try:
                remove(data_files_file)
            except OSError:
                pass

def make_dists():
    prebuilt_platform_root = path.join("dtls", "prebuilt")
    for platform in listdir(prebuilt_platform_root):
        config = {"MANIFEST_DIR": path.join(prebuilt_platform_root, platform)}
        execfile(path.join(prebuilt_platform_root, platform, "manifest.pycfg"),
                 config)
        files = map(lambda x: "dtls/prebuilt/" + platform + "/" + x,
                    config["FILES"])
        argv.append("--formats=" + config["FORMATS"])
        invoke_setup([('dtls', files)])
        del argv[-1]
        for dist_format in config["FORMATS"].split(','):
            source_name = path.join(DIST_DIR,
                                    NAME + "-" + VERSION +
                                    FORMAT_TO_SUFFIX[dist_format])
            target_name = path.join(DIST_DIR,
                                    NAME + "-" + VERSION +
                                    ".sdist_with_openssl." +
                                    config["ARCHITECTURE"] +
                                    FORMAT_TO_SUFFIX[dist_format])
            try:
                remove(target_name)
            except OSError:
                pass
            rename(source_name, target_name)
    # Finally the distribution without prebuilts
    argv.append("--formats=zip,gztar")
    invoke_setup()

if __name__ == "__main__":
    if argv[-1] == "--prebuilts":
        del argv[-1]
        make_dists()
    else:
        invoke_setup()
