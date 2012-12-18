#!/usr/bin/env python
# PyDTLS setup script.

# Copyright 2012 Ray Brown
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
VERSION = "0.1.0"

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
                data_files = []
        data_files.append(('dtls', ["NOTICE", "LICENSE", "README.txt"]),)
        setup(name=NAME,
              version=VERSION,
              description="Python Datagram Transport Layer Security",
              author="Ray Brown",
              author_email="code@liquibits.com",
              url="https://github.com/rbit/pydtls",
              license="LICENSE",
              long_description=open("README.txt").read(),
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
