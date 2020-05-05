==========
Deployment
==========

**Warning:** Lightnion is an alpha-stage software which is not fit for
production at this point.

Lightnion needs to be deployed from sources. It is constituted of two parts, a
JavaScript client and a proxy between the client and the guard relay on Tor
network. 

Prerequisites
=============

Lightnion is a two-parts software constituted of:

- a Javascript client called from the web browser
- a proxy running on a server

The proxy requires at least 2 GiB of RAM, and was tested successfully only on
Linux. The proxy also need to connect to the Tor network, which can be done
either by simulationg it with Chutney or using the real Tor network.

To test Lightnion proxy on a proper server, you also need a hidden Tor relay on
the same machine where Lightnion is running. We advise to run the guard relay
on the same server as the Lightnion proxy. To install the hidden Tor relay,
please refers to the `documentation from the Torproject
<https://2019.www.torproject.org/docs/debian.html.en>`_, `their wiki
<https://trac.torproject.org/projects/tor/wiki/TorRelayGuide>`_, or the
documentation of the Linux distribution installed on the server.

Installation
============

Installation of the Proxy
-------------------------

The proxy requires Python 3.7 or superior and the libraries listed in the files
`requirements.txt` and `requirements-proxy.txt`, which can be installed with
`pip`. We tested the proxy on Debian Buster, it likely also work on other
Linux distributions which provide Python 3.7, but we did not test the proxy on
them.

We advise to use git to retrieve the sources.
.. code-block::

    $ git clone  --recurse-submodules https://github.com/spring-epfl/lightnion.git
    $ cd lightnion

We strongly advise to install the Lightnion proxy in a virtual environment.
.. code-block::

    $ virtualenv --python=python3 venv
    $ . venv/bin/activate

The dependances can be installed with `pip`.
.. code-block::

    $ pip install -r requirements.txt -r requirements-proxy.txt


Building the JavaScript Client
------------------------------

The minified bundle of the Javacript client needs to be build. We wrote a
Makefile to simplify this task.
.. code-block::

    $ cd js-client
    $ make

The resulting file `lightnion.bundle.js` is a bundle containing Lightnion and
all its dependancies. It can be served by a web server, and linked in a web
page as any other JS library.


Testing Lightnion Locally
=========================

For testing Lightnion locally, you might prefer to simulte the Tor network to which the proxy is going to connect. To do so, we provide a script to configure the network simulated by Chutned.
.. code-block::

   $ git clone https://git.torproject.org/chutney.git
   $ cp lightnion/tools/chutney/small-chut chutney
   $ cd chutney

You might also want to disable the sandboxing, we provide a patch to do so.
.. code-block::

   $ git apply ../lightnion/tools/chutney/sandbox_patch

Once the installation is done, you can start Chutney with the commands.
.. code-block::

   $ cd chutney
   $ ./small-chut

To Test Lightnion locally, it is necessary to run a local web server to
dispatch the Lightnion Javascript client. (Here is an example with Python.)
.. code-block::

    $ cd js-client/demo
    $ python -m http.server

Then the proxy can be started with these commands (Here, the proxy is running
in a virtual environment).
.. code-block::

    $ source env/bin/activate
    (venv)$ python -m lightnion.proxy -vvv -s 127.0.0.1:9050 -c 8000 -d 9051


Web Server configuration
========================

For testing Lightnion on a proper server, you need a webserver like Apache or
Nginx, and the compiled Lightnion bundle.  

By default, the connection between the client and proxy server is in clear. If
you prefer to use a secure connection, the sources of the Javascript client
needs to be slightly modified to accept HTTPS connection, and the ports need to
be changed to 443. In a later version, TLS will be enabled by default, and a
flag will be needed to use an insecure connection.

A Typical Nginx configuration for a proxy server looks like this:

.. literalinclude:: lightnion-nginx-tls.conf


Automatic Startup and Process Monitoring
========================================

We can ensure Lightnion is running by configuring systemd or another init
system to restart the process when necessary, and optionally to notify the
administrator when the service is restarted.

.. literalinclude:: lightnion.service

.. literalinclude:: lightnion-fail.service
