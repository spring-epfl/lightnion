lighttor: Tor portable to the browser
=====================================

**Note: lightlor is still at its early stages of development, do NOT use it for
anonymity.**

Content
-------

 - [Introduction](#introduction)
 - [Quick Setup](#quick-setup)
 - [Requirements](#requirements)
 - [Frequently Asked Questions](#frequently-asked-questions)
 - [Contribute](#contribute)
 - [Contact](#contact)
 - [License](#license)

Introduction
------------

Kids these days worry about a lot of things:
 - users wanting services designed with privacy in mind.
 - users not wanting to download more than a webpage.
 - users not wanting latency and high resources usage.

**Lighttor** enables kids to build such applications in a world made of
browsers that are not the [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en).

It provides the following components:
 - a lightweight client that can be easily embedded within a webpage.
 - a forward proxy that does some heavy-lifting for clients.
 - a reverse proxy that does the rest of the heavy-lifting.

**Lighttor** lightweight client is a library that your javascript uses to talk
through Tor. Its forward proxy removes raw TCP between sandboxed code and onion
routers. Its reverse proxy removes the need of running TLS or HTTPS within a
webpage.

It is also **not** production ready.

Checkout [Frequently Asked Questions](#frequently-asked-question) for more
details.

Quick setup
-----------

Clone the repository and add it to your `PYTHONPATH`:
```sh
git clone --recurse-submodules https://github.com/spring-epfl/lighttor
cd lighttor
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD"
```

There is no online documentation for now. You'll find some examples under
`./examples`.


Requirements
------------

We do recommend using `chutney`, you'll find some instructions
within `./tools/chutney`.

**Tested with `Python 3.6.5` against
`Tor version 0.3.3.6 (git-7dd0813e783ae16e)`.**

If you need support for an older python or a newer Tor, please open an issue.

Frequently Asked Questions
--------------------------

If you have some questions, please open an issue starting with
`[FAQ] <your-question>` to get an answer or [contact us](#contact).

You'll find below some answers to some frequently asked questions:

 - [Are you attempting to replace the Tor Browser?](#are-you-attempting-to-replace-the-tor-browser)
 - [What can I expect lighttor to do for me?](#what-can-i-expect-lighttor-to-do-for-me)
 - [How are you going to do that?](#how-are-you-going-to-do-that)
 - [Why doing things in a browser?](#why-doing-things-in-a-browser)
 - [Why javascript? Is is then unsafe?](#why-javascript-is-is-then-unsafe)
 - [Does it protects me if I disable javascript?](#does-it-protects-me-if-i-disable-javascript)
 - [Why not hacking the official Tor client?](#why-not-hacking-the-official-Tor-client)
 - [Why are you not using stem to do that?](#why-are-you-not-using-stem-to-do-that)
 - [Why are you not using a pluggable transport to do that?](#why-are-you-not-using-a-pluggable-transport-to-do-that)

### Are you attempting to replace the [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en)?

_No._

If you are an user worried about your privacy, using the Tor Browser is a [good
starting point](https://www.torproject.org/docs/faq.html.en#WhatIsTor).

If you do not use the Tor Browser but
[still care](https://www.torproject.org/docs/faq.html.en#TBBOtherBrowser)
about privacy, you may someday enjoy web services that uses lighttor.

If you are trying to build a web service designed with privacy in mind
and that works on any browser, lighttor may
[help you](#what-can-i-expect-lighttor-to-do-for-me).

### What can I expect lighttor to do for me? 

_Not much if you are not building a web-based application._

First, start by reading:
[Are you attempting to replace the Tor Browser?](#are-you-attempting-to-replace-the-tor-browser).

Now, if you are the one trying to build such privacy-enabled service, there is
not much that you can do against
[traffic analysis](https://www.torproject.org/about/overview.html.en#whyweneedtor).
Most chooses to tell their privacy-minded and tech-savvy users to get the Tor
Browser and leave other kinds of users aside.

**Lighttor brings a different compromise into the picture:** your
privacy-minded and tech-savvy users will still be able to protect themselves,
however the other kinds will also interact with you through Tor and will have
some form of protection.

The trick is that you will not be able to distinguish privacy-minded users from
other kinds of users. Thus, even getting few users to run signed software that
checks if your service does not misbehave can provide good incentives to remain
honest.

To sum up, if you build such "privacy by default" service with lighttor, all
your users talk to you through Tor, get some protection and can at least trust
your reputation against the permanent scrutiny of anonymous privacy-minded
users hiding in the crowd.

**Note that lighttor is still in the early stages of its development and need
more work to enforce those properties.**

### How are you going to do that?

_No idea, yet._

Lighttor is first and foremost a research project, its whole job is to figure
out how to achieve its goals.

Please open an issue or [contact us](#contact) if you spot problems, have some
criticism or want to [contribute](#contribute).

### Why doing things in a browser?

_Because it is useful._

There is the [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en)
and [several](https://www.torproject.org/docs/faq.html.en#TBBSocksPort)
[other](https://guardianproject.info/apps/orbot/)
[ways](https://tails.boum.org/) to use the Tor network and its capabilities as
an user.

Lighttor aims to bring Tor to users with nothing more than loading a webpage.
Hence yes: it does things in a browser.

### Why javascript? Is is then unsafe?

_Because browsers. Not more than running any web-based application._

The full answer is closely related to:
 - [Why doing things in a browser?](#why-doing-things-in-a-browser)
 - [What can I expect lighttor to do for me?](#what-can-i-expect-lighttor-to-do-for-me)

Lighttor targets mostly web-based applications where the user only open a
webpage to use Tor. It can not afford nice things such as native clients,
extensions or the Tor Browser itself: the only way to go was to embed some
javascript in the webpage.

As an user of a web-based service, you already put some trust in your service
that delivers nice code with no malicious intent. Lighttor only adds to this
code a tiny library that gives a way for the service to interact with its
servers through Tor.

Lighttor is only as small step towards an ecosystem that brings privacy to the
masses. It does provide few other components that may help users to protect
themselves, however it will not prevent design mistakes in applications or some
malpractices.

### Does it protects me if I disable javascript?

_Lighttor does not provide any kind of protection before it is executed._

This question is best answered through a case study: imagine that lighttor is
integrated into an instant messaging client written in javascript. You first
download the webpage, then the client kicks in and send/receive all messages
through the Tor network.

Every user that keeps its browser tab open for a long time starts to look the
same, providing some form of anonymity. However, if you disabled javascript in
the first place, you never were an user of this instant messaging service in
the first place.

### Why not hacking the official Tor client?

_Because it may have been counterproductive._

Lighttor was build with a side task of understanding in details what can be/can
not be done within the Tor protocol, and what needed to be implemented in
order to get the thing into a browser. This implementation acts as a
side-effect of such work.

Note that some components of the official client are used or planned to be
used, mostly for the sensitive parts.

### Why are you not using [stem](http://stem.torproject.org/) to do that?

Closely related to:
[Why not hacking the official Tor client?](#why-not-hacking-the-official-Tor-client)

Note that some components of stem have been previously used and some are still
used.

### Why are you not using a [pluggable transport](https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt) to do that?

_For now._

Implementing a proper pluggable transport can enable lighttor to be more easily
integrated within the existing Tor ecosystem. However building such pluggable
transport is for now not a priority, lighttor needs more work to get to this
point.

---

Contribute
----------

Feel free to contribute!

If you want to make your time worth, do not hesitate to [contact us](#contact)
and to tell us what you want to do.

Contact
-------

Feel free to contact us:
```
 - carmela [dot] troncoso [at] epfl [dot] ch
 - wouter [dot] lueks [at] epfl [dot] ch
 - matthieu [at] daumas [dot] me
```

If you have bug reports or feature suggestions, please open an issue.

License
-------

This software is licensed under
[some license](LICENSE.txt_REPLACE_BEFORE_FIRST_RELEASE).
© 2018 Spring Lab (EPFL) and contributors.

Note that the aforementioned `some license` mention should have been replaced
before the distribution of the project. If you are able to read this, please
[contact us](#contact) to report the issue or to obtain a copy of the license
we choose for the project.
