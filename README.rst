========
massexec
========

Massexec is a Python script that allows to copy and execute a specified script
on multiple remote hosts simultaneously.


Description
===========

The purpose of massexec is decreasing total execution time of the same script
on several remote hosts. It's needed to establish two or more SSH connection
for this goal while using scp and ssh programs. Massexec makes only one SSH
connection and uses different SSH channel for copying a script and additional
files and to invoke a script on a remote host. This allows to avoid multiple
SSH negotiation. Also massexec runs a scripts on several hosts simultaneously
that significantly reduces total execution time.

Limitations
-----------

1. Massexec uses only public key authentication with an authentication agent.
   Therefore before using this scrip you should install your public keys on
   remote hosts and start an authentication agent with your private keys,
   i.e. ssh-agent, GNOME Keyring, KWallet.

2. Massexec doesn't check a fingerprint of a remote host's public key.


Requirements
============

The following are required to run massexec:

* Python 2.6 or 2.7

* Twisted 12.0 or above


Installation
============

Install massexec with::

    # python setup.py install


Running
=======

Run 'massexec.py --help' to get help message::

    $ massexec.py --help
    Usage: massexec.py [options] host1 [host2 [host3...]]
    Options:
      -v, --log        Enable logging (defaults to stderr)
      -u, --user=      The username to log in as on the remote host
      -s, --script=    The script file to copy and execute on remote host
      -f, --file=      The additional file to copy to the remote host
      -m, --multiple=  The number of simultaneous connections [default: 10]
      -b, --bind=      The source address of the connections
          --version    Display Twisted version and exit.
          --help       Display this help and exit.


License
=======

Massexec is published under the 3-Clause BSD license.
