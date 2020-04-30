==========
Deployment
==========

**Warning:** Lightnion is an alpha-stage software which is not fit for
production at this point.

Prerequisites
=============

Test on local machine
---------------------

Any modern hardware should have enough resources to run Lightnion. Chutney can
be used to simulate a Tor network to which Lichtnion can connect.

Test on real environment
------------------------

To test the Lightnion proxy in a real environment, a server with at least 1 GB
of memory and a reasonnable amount of bandwidth is needed. In the mode where
the Tor circuit is computed in the proxy 2 GB of memory are necessary.

To function properly, the Lightnion proxy needs to interact with a Tor relay,
which will act as the guard of all Tor circuits build with Lightnion. To
install a Tor relay on your system, please refers to the `documentation from
the Tor project <https://trac.torproject.org/projects/tor/wiki/TorRelayGuide>`,
or the documentation of your distribution.

Also, to serve the Javascript client, encrypt, and redirect the proxy ports,
a web server like Nginx is recommended. Please refer to the documentation of
your distribution to install one.

Installation
============

At this stage of the development, there still hasn't any distribution package
for Lightnion. This software needs to be deployed from sources. It is
constituted of two parts, a JavaScript client and a proxy between the client
and the Tor network, which can be run either on the same server or on different
machines. It is also advised to run a hidden Tor entry point on the server to
act as the guard relay for the proxy.


Installation of the Proxy
-------------------------

The proxy requires Python 3.7 or superior and the libraries listed in the files
`requirements.txt` and `requirements-proxy.txt`, which can be installed with
`pip`. The proxy was tested on Debian Buster, it likely also work on other
Linux distributions providing Python 3.7, but was not tested on them.

It is advised to use git to retrieve the sources.
::
    $ git clone  --recurse-submodules https://github.com/spring-epfl/lightnion.git
    $ cd lightnion

It is strongly advised to install the Lightnion proxy in a virtual environment.
::
    $ virtualenv --python=python3 venv
    $ . venv/bin/activate

The dependances can be installed with `pip`.
::
    $ pip install -r requirements.txt -r requirements-proxy.txt

To work, the proxy needs to interact with a tor relay, which will be the entry
point in the tor network. Therefore it is adviseable to install a hidden Tor
relay on the machine. To do so, refer to the
`Tor documentation <https://2019.www.torproject.org/docs/debian.html.en>`.

Installing Chutney (for testing locally)
----------------------------------------



Building the JavaScript Client
------------------------------

The minified bundle of the Javacript client needs to be build. A Makefile
exists to simplify its building process
::
    $ cd js-client
    $ make

The resulting file `lightnion.bundle.js` is a bundle containing Lightnion and
all its dependancies. It can be served by a web server, and linked in a web
page as any other JS library.


Testing Lightnion Locally
=========================

To Test Lightnion locally, it is necessary to run a local web server to
dispatch the Lightnion Javascript client. This can be done easilly with
Python's HTTP server
::
    $ cd js-client/demo
    $ python -m http.server

then the proxy can be started with
::
    $ source env/bin/activate
    (venv)$ python -m lightnion.proxy -vvv -s 127.0.0.1:9050 -c 8000 -d 9051


Web Server configuration
========================

For a test on a real environment, a proper web server like Nginx or Apache is
required, and the demo files copied to the root directory of the web server
along with the Lightnion bundle.

By default, the connection between the client and proxy server is in clear.
Ideally, this connection should be secure, and this will probably change in the
near future.

A Typical Nginx configuration for a proxy server will look like this:

.. literalinclude:: lightnion-nginx-tls.conf


Automatic Startup and Process Monitoring
========================================

To ensure Lightnion is running, systemd or an other init system can be used to
notify the administrator and restart the process if necessary.

.. literalinclude:: lightnion.service

.. literalinclude:: lightnion-fail.service
