#!/bin/bash

# Get script dir.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

# Build targets.
export PATH=~/.platformio/penv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:~/n/bin:$PATH

TEST=${SCRIPT_DIR}/examples/BasicIOTest/BasicIOTest.ino
pio ci --lib="." --verbose --board=uno --board=micro --board=leonardo --board=megaatmega1280 --board=megaatmega2560 --board=huzzah ${TEST}

exit $?