# log4j_checker_beta

This script is used to perform a fast check if your server is possibly affected by CVE-2021-44228 (the log4j vulnerability).

It can also optionally perform a full-disk scan for log4j-core-*.jar and for classes named "JndiLookup" inside every jar.
This scan runs in low-priority mode using ionice.

## Run with:

wget https://raw.githubusercontent.com/thd-stihl/log4j_checker_beta/main/log4j_checker_beta.sh -q -O - |bash

## dependencies

The command `locate` has to to be installed, be sure to have locate up-to-date with:

    sudo updatedb

The command `unzip` also needs to be installed, to inspect the jar files.
