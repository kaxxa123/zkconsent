#!/bin/sh
hexdump -v -e '1/1 "%02x"' "$1"