python-locfg
============

Python-locfg is an implementation of the Lights-Out Configuration
utility for HP's iLO management ASIC.

Python-locfg can be used to send RIBCL XML scripts to iLOs of
any version or you may use Python-locfg to learn how to implement
your own communication with iLO.

Python-locfg also implements some simple helper functions like
adding a user or flashing firmware.  There is no magic to the
helper functions -- they were just function I needed.

Usage
=====
locfg -s server [-l logfile] -f inputfile [-u username -p password]
Note: Use -u and -p with caution as command line options are
      visible on Linux.

All options:
    -s, --server:     Specify the server name/IP address
    -l, --logfile:    Where to log output.
    -f, --input:      The input script.
    -u, --username:   Username.
    -p, --password:   Password.
    -i, --iloversion: iLO hardware version (1, 2 3 or 4).
    -v, --verbose:    Verbose mode.
    -x, --xmlfix:     Do some basic fixups on the returned XML.
    -z, --firmware:   Update the iLO firmware on the target server.
    -m, --m2crypto:   Use the M2Crypto library for SSL connections.
    -a, --adduser:    Add/update a user (-a username:password).
    -h, -?, --help:   This text.

