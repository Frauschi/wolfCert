#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# CTest emulator that runs each test with SIGPIPE ignored; ctest resets
# SIGPIPE for its children, but SIG_IGN survives exec.
trap '' PIPE
exec "$@"
