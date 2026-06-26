#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Bootstrap the autoconf build system. Run once after cloning (or after
# touching configure.ac or any Makefile.am).

set -e
mkdir -p build-aux m4
autoreconf --install --force --verbose
