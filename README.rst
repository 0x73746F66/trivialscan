Trivial Scanner
===============

|PyPI download month| |PyPi version|

Validate the security of your TLS connections so that they deserve your
trust.

Because, no one wants to write several hundred lines of code for every
project that uses micro-services, internal APIs, zero-trust, etc. where
you probably should be doing more then just the basic built-in OpenSSL
hostname and root trust store checks.

Package ``trivialscan`` provides a command-line tool ``trivial``
which contacts an SSL/TLS server and obtains some information on its
configuration. It aims at providing equal or better functionality of
Internet-based tools like `Qualys SSL Server
Test <https://www.ssllabs.com/ssltest/>`__ without the requirement of
the target server being internet connected.

You can also use ``trivial scan`` on your internal network, DevOps pipeline, or local computer,
to test your servers while they are being developed.

.. |PyPI download month| image:: https://img.shields.io/pypi/dm/trivialscan.svg
   :target: https://pypi.python.org/pypi/trivialscan/
.. |PyPi version| image:: https://badgen.net/pypi/v/trivialscan/
   :target: https://pypi.com/project/trivialscan
